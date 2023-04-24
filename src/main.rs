use hex;
use multiparty_signature_test::{KeygenSession1, ReceiveStep, SendAllStep, SendOneStep, SignSession1, State, strerror};
use std::env;
use std::fs::File;
use std::io::{Read, Result, stdout, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let Some(cmd) = args.next() else {
        return Err(strerror("need to specify a command"));
    };
    if cmd == "init" {
        init(args)
    } else if cmd == "info" {
        info(args)
    } else if cmd == "generate-key" {
        generate_key(args)
    } else if cmd == "derive-key" {
        derive_key(args)
    } else if cmd == "sign" {
        sign(args)
    } else {
        Err(strerror("unknown command"))
    }
}

fn next_arg(args: &mut env::Args) -> Result<String> {
    args.next().ok_or_else(|| strerror("too few arguments"))
}

fn end_args(mut args: env::Args) -> Result<()> {
    args.next().map_or(Ok(()), |_| Err(strerror("too many arguments")))
}

const STATE_FILENAME: &str = "state";

fn load_state() -> Result<State> {
    let mut bytes = Vec::new();
    File::open(STATE_FILENAME)?.read_to_end(&mut bytes)?;
    State::from_bytes(bytes.as_slice()).ok_or_else(|| strerror("malformed state file"))
}

fn save_state(state: State, new: bool) -> Result<()> {
    let bytes = state.to_bytes();
    File::options().write(true).truncate(true).create(true).create_new(new).open(STATE_FILENAME)?.write_all(bytes.as_slice())?;
    Ok(())
}

fn init(args: env::Args) -> Result<()> {
    end_args(args)?;
    save_state(State::init(), true)?;
    Ok(())
}

fn info(args: env::Args) -> Result<()> {
    end_args(args)?;
    let state = load_state()?;
    let (node_key, extra) = state.info();
    writeln!(stdout(), "Node key: {}", hex::encode(node_key))?;
    if let Some((n, t, this_index, master_key, node_keys)) = extra {
        writeln!(stdout(), "Node {} of {}/{}, master key: {}", this_index + 1, t, n, hex::encode(master_key))?;
        writeln!(stdout(), "Node keys:")?;
        for key in node_keys {
            writeln!(stdout(), "{}", hex::encode(key))?;
        }
    }
    Ok(())
}

fn parse_addr(s: &str) -> Result<SocketAddr> {
    s.parse().map_err(|_| strerror("invalid address"))
}

fn generate_key(mut args: env::Args) -> Result<()> {
    let arg = next_arg(&mut args)?;
    let mut state;
    if let Ok(t) = arg.parse() {
        let n = args.len() + 1;
        if !KeygenSession1::params_valid_leader(n, t) {
            return Err(strerror("invalid parameters"));
        }
        state = load_state()?;
        let Some(session) = KeygenSession1::new_leader(&state, n, t) else {
            return Err(strerror("invalid state"));
        };
        let addrs: Vec<_> = args.map(|a| parse_addr(&a)).collect::<Result<_>>()?;
        let mut conns: Vec<_> = addrs.into_iter().map(|a| TcpStream::connect(a)).collect::<Result<_>>()?;
        for (i, mut conn) in conns.iter().enumerate() {
            conn.write_all(&(n as u32).to_le_bytes())?;
            conn.write_all(&(t as u32).to_le_bytes())?;
            conn.write_all(&((i + 1) as u32).to_le_bytes())?;
            conn.flush()?;
        }
        let session = leader_broadcast_step(&mut conns, session)?;
        let session = leader_multicast_step(&mut conns, session)?;
        let session = leader_multicast_step(&mut conns, session)?;
        let session = leader_multicast_step(&mut conns, session)?;
        session.update_state(&mut state);
    } else {
        let addr = parse_addr(&arg)?;
        end_args(args)?;
        let mut conn = TcpListener::bind(addr)?.accept()?.0;
        let mut buf = [0; 12];
        conn.read_exact(&mut buf)?;
        let n = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let t = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let this_index = u32::from_le_bytes(buf[8..].try_into().unwrap()) as usize;
        if !KeygenSession1::params_valid_signer(n, t, this_index) {
            return Err(strerror("invalid parameters"));
        }
        state = load_state()?;
        let Some(session) = KeygenSession1::new_signer(&state, n, t, this_index) else {
            return Err(strerror("invalid state"));
        };
        let session = signer_broadcast_step(&mut conn, session)?;
        let session = signer_multicast_step(&mut conn, session)?;
        let session = signer_multicast_step(&mut conn, session)?;
        let session = signer_multicast_step(&mut conn, session)?;
        session.update_state(&mut state);
    }
    save_state(state, false)
}

fn derive_key(mut args: env::Args) -> Result<()> {
    let account_id = next_arg(&mut args)?;
    let email = next_arg(&mut args)?;
    end_args(args)?;
    let state = load_state()?;
    let Some(pk) = state.derive_key(&account_id, &email) else {
        return Err(strerror("not a main node or keys are not set up"));
    };
    writeln!(stdout(), "{}", hex::encode(pk))?;
    Ok(())
}

fn sign(mut args: env::Args) -> Result<()> {
    let state = load_state()?;
    let Some((n, t, this_index)) = state.inf() else {
        return Err(strerror("invalid state"));
    };
    if this_index == 0 {
        let account_id = next_arg(&mut args)?;
        let email = next_arg(&mut args)?;
        let message = hex::decode(next_arg(&mut args)?).map_err(|_| strerror("invalid message"))?;
        if args.len() != n - 1 {
            return Err(strerror("invalid number of arguments"));
        }
        let mut participants = Vec::with_capacity(t);
        participants.push(0);
        let mut addrs = Vec::with_capacity(t - 1);
        for i in 1 .. n {
            let arg = next_arg(&mut args)?;
            if arg != "-" {
                if participants.len() == t {
                    return Err(strerror("invalid number of arguments"));
                }
                participants.push(i);
                addrs.push(parse_addr(&arg)?);
            }
        }
        if participants.len() != t {
            return Err(strerror("invalid number of arguments"));
        }
        let Some((key, message, session)) = SignSession1::new_leader(&state, participants.clone(), &account_id, &email, message) else {
            unreachable!();
        };
        let mut conns: Vec<_> = addrs.into_iter().map(|a| TcpStream::connect(a)).collect::<Result<_>>()?;
        for conn in &mut conns {
            for j in &participants {
                conn.write_all(&u32::try_from(*j).unwrap().to_le_bytes())?;
            }
            conn.write_all(&key)?;
            conn.write_all(&u32::try_from(message.len()).unwrap().to_le_bytes())?;
            conn.write_all(&message)?;
            conn.flush()?;
        }
        let session = leader_broadcast_step(&mut conns, session)?;
        let session = leader_multicast_step(&mut conns, session)?;
        let session = leader_multicast_step(&mut conns, session)?;
        let sig = leader_unicast_step(&mut conns, session)?;
        writeln!(stdout(), "Signature: {}", hex::encode(sig))?;
    } else {
        let addr: SocketAddr = parse_addr(&next_arg(&mut args)?)?;
        end_args(args)?;
        let mut conn = TcpListener::bind(addr)?.accept()?.0;
        let mut buf = vec![0; 4 * t + 36];
        conn.read_exact(&mut buf)?;
        let mut participants = Vec::with_capacity(t);
        for i in 0..t {
            participants.push(u32::from_le_bytes(buf[4 * i .. 4 * i + 4].try_into().unwrap()) as usize);
        }
        if !(participants[0] == 0 && participants.iter().all(|i| *i < n) &&
            participants.iter().zip(&participants[1..]).all(|(i, j)| i < j) &&
            participants.iter().any(|i| *i == this_index)) {
            return Err(strerror("invalid parameters"));
        }
        let key = buf[4 * t .. 4 * t + 32].try_into().unwrap();
        let message_len = u32::from_le_bytes(buf[4 * t + 32 ..].try_into().unwrap()) as usize;
        let mut message = vec![0; message_len];
        conn.read_exact(&mut message)?;
        let Some(session) = SignSession1::new_signer(&state, participants, key, message) else {
            unreachable!();
        };
        let session = signer_broadcast_step(&mut conn, session)?;
        let session = signer_multicast_step(&mut conn, session)?;
        let session = signer_multicast_step(&mut conn, session)?;
        signer_unicast_step(&mut conn, session)?;
    }
    Ok(())
}

fn leader_broadcast_step<T: SendOneStep>(conns: &mut [TcpStream], session: T) -> Result<<T::Next as ReceiveStep>::Next>
  where T::Next: ReceiveStep {
    let s = session.size();
    let n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n).unwrap()];
    let session = session.send(|buf| Ok(bufs[..s].copy_from_slice(buf)))?;
    for (i, mut conn) in conns.iter().enumerate() {
        conn.read_exact(&mut bufs[(i + 1) * s .. (i + 2) * s])?;
    }
    for (i, mut conn) in conns.iter().enumerate() {
        conn.write_all(&bufs[.. (i + 1) * s])?;
        conn.write_all(&bufs[(i + 2) * s ..])?;
        conn.flush()?;
    }
    session.recv(|i, buf| Ok(buf.copy_from_slice(&bufs[i * s .. (i + 1) * s])))
}

fn signer_broadcast_step<T: SendOneStep>(conn: &mut TcpStream, session: T) -> Result<<T::Next as ReceiveStep>::Next>
  where T::Next: ReceiveStep {
    let session = session.send(|buf| conn.write_all(buf))?;
    conn.flush()?;
    session.recv(|_, buf| conn.read_exact(buf))
}

fn leader_multicast_step<T: SendAllStep>(conns: &mut [TcpStream], session: T) -> Result<<T::Next as ReceiveStep>::Next>
  where T::Next: ReceiveStep {
    let s = session.size();
    let n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n).unwrap().checked_mul(n - 1).unwrap()];
    let session = session.send(|i, buf| Ok(bufs[i * s .. (i + 1) * s].copy_from_slice(buf)))?;
    for (i, mut conn) in conns.iter().enumerate() {
        conn.read_exact(&mut bufs[i * n * s .. (i * n + i + 1) * s])?;
        if i < n - 2 {
            conn.read_exact(&mut bufs[((i + 1) * n + i + 2) * s .. (i + 2) * n * s])?;
        }
    }
    for (i, mut conn) in conns.iter().enumerate() {
        for j in 0 .. n - 1 {
            conn.write_all(&bufs[(j * n + i + 1) * s .. (j * n + i + 2) * s])?;
        }
        conn.flush()?;
    }
    session.recv(|i, buf| Ok(buf.copy_from_slice(&bufs[(i - 1) * n * s .. ((i - 1) * n + 1) * s])))
}

fn signer_multicast_step<T: SendAllStep>(conn: &mut TcpStream, session: T) -> Result<<T::Next as ReceiveStep>::Next>
  where T::Next: ReceiveStep {
    let session = session.send(|_, buf| conn.write_all(buf))?;
    conn.flush()?;
    session.recv(|_, buf| conn.read_exact(buf))
}

fn leader_unicast_step<T: SendOneStep>(conns: &mut [TcpStream], session: T) -> Result<<T::Next as ReceiveStep>::Next>
  where T::Next: ReceiveStep {
    let s = session.size();
    let n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n - 1).unwrap()];
    let session = session.send(|_| unreachable!())?;
    for (i, mut conn) in conns.iter().enumerate() {
        conn.read_exact(&mut bufs[i * s .. (i + 1) * s])?;
    }
    session.recv(|i, buf| Ok(buf.copy_from_slice(&bufs[(i - 1) * s .. i * s])))
}

fn signer_unicast_step<T: SendOneStep>(conn: &mut TcpStream, session: T) -> Result<()> {
    session.send(|buf| conn.write_all(buf))?;
    conn.flush()
}
