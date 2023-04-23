use hex;
use std::env;
use std::fs::File;
use std::io::{Error, Result};
use crate::State;

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let Some(cmd) = args.next() else {
        return Err(Error::other("need to specify a command"));
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
        Err(Error::other("unknown command"))
    }
}

fn next_arg(args: &mut env::Args) -> Result<String> {
    args.next().ok_or_else(|| Error::other("too few arguments"))
}

fn end_args(args: env::Args) -> Result<()> {
    args.next().map(|_| ()).ok_or_else(|| Error::other("too many arguments"))
}

const state_filename = "state";

fn load_state() -> Result<State> {
    let mut bytes = Vec::new();
    File::open(state_filename)?.read_to_end(&mut bytes)?;
    State::from_bytes(bytes.as_slice()).ok_or_else(|| Error::other("malformed state file"))
}

fn save_state(state: State, new: bool) -> Result<()> {
    let bytes = state.to_bytes();
    File::options().write(true).truncate(true).create(true).create_new(new).open(state_filename)?.write_all(bytes.as_slice())?;
    Ok(())
}

fn init(mut args: env::Args) -> Result<()> {
    end_args(&mut args)?;
    save_state(State::new(), true)?;
    Ok(())
}

fn info(mut args: env::Args) -> Result<()> {
    end_args(&mut args)?;
    let (node_key, extra) = load_state()?.info();
    writeln!(io::stdout(), "Node key: {}", hex::encode(node_key))?;
    if let Some((n, t, this_index, master_key, node_keys)) = extra {
        writeln!(io::stdout(), "Node {} of {}/{}, master key: {}", this_index + 1, t, n, hex::encode(master_key))?;
        writeln!(io::stdout(), "Node keys:")?;
        for key in node_keys {
            writeln!(io::stdout(), "{}", hex::encode(key))?;
        }
    }
    Ok(())
}

fn generate_key(mut args: env::Args) -> Result<()> {
    let arg = next_arg(&mut args)?;
    if let Ok(t) = arg.parse() {
        let n = args.len() + 1;
        if !KeygenSession1::params_valid_leader(n, t) {
            return Err(Error::other("invalid parameters"));
        }
        let state = load_state()?;
        let Some(session) = KeygenSession1::new_leader(state, n, t) else {
            return Err(Error::other("invalid state"));
        };
        let addrs = args.map(|a| a.parse()).collect()?;
        let mut conns = addrs.into_iter().map(|a| TcpStream::connect(a)).collect()?;
        for (i, conn) in conns.iter().enumerate() {
            conn.write_all((n as u32).to_le_bytes())?;
            conn.write_all((t as u32).to_le_bytes())?;
            conn.write_all((i + 1 as u32).to_le_bytes())?;
            conn.flush()?;
        }
        let session = leader_broadcast_step(conns, session)?;
        let session = leader_multicast_step(conns, session)?;
        let session = leader_multicast_step(conns, session)?;
        let session = leader_multicast_step(conns, session)?;
        session.update_state(&mut state);
    } else {
        let addr = arg.parse()?;
        end_args(&mut args)?;
        let mut conn = TcpListener::bind(addr)?.accept()?.0;
        let mut buf = [0; 12];
        conn.read_exact(buf)?;
        let n = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let t = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let this_index = u32::from_le_bytes(buf[8..].try_into().unwrap()) as usize;
        if !KeygenSession1::params_valid_signer(n, t, this_index) {
            return Err(Error::other("invalid parameters"));
        }
        let state = load_state()?;
        let Some(session) = KeygenSession1::new_signer(state, n, t, this_index) else {
            return Err(Error::other("invalid state"));
        };
        let session = signer_broadcast_step(conn, session)?;
        let session = signer_multicast_step(conn, session)?;
        let session = signer_multicast_step(conn, session)?;
        let session = signer_multicast_step(conn, session)?;
        session.update_state(&mut state);
    }
    save_state(state, false)
}

fn derive_key(mut args: env::Args) -> Result<()> {
    let account_id = next_arg(&mut args)?, email = next_arg(&mut args)?;
    end_args(&mut args);
    let state = load_state()?;
    let Some(pk) = state.derive_key(&account_id, &email) else {
        return Err(Error::other("not a main node or keys are not set up"));
    };
    writeln!(io::stdout(), "{}", hex::encode(pk))?;
    Ok(())
}

fn sign(mut args: env::Args) -> Result<()> {
    let state = load_state()?;
    let Some((n, t, this_index)) = state.inf() else {
        return Err(Error::other("invalid state"));
    }
    if this_index == 0 {
        let account_id = next_arg(&mut args)?;
        let email = next_arg(&mut args)?;
        let message = hex::decode(next_arg(&mut args)?)?;
        if args.len() != n {
            return Err(Error::other("invalid number of arguments"));
        }
        let mut participants = Vec::with_capacity(t);
        participants.push(0);
        let mut addrs = Vec::with_capacity(t - 1);
        for i in ..n {
            let arg = next_arg(&mut args)?;
            if arg != "-" {
                if participants.len() == t {
                    return Err(Error::other("invalid number of arguments"));
                }
                participants.push(i);
                addrs.push(arg.parse()?);
            }
        }
        if participants.len() != t {
            return Err(Error::other("invalid number of arguments"));
        }
        let Some((key, message, session)) = SignSession1::new_leader(state, participants.clone(), account_id, email, message) else {
            unreachable!();
        };
        let mut conns = addrs.into_iter().map(|a| TcpStream::connect(a)).collect()?;
        for (i, conn) in conns.iter().enumerate() {
            for j in participants {
                conn.write_all(u32::try_from(j).unwrap().to_le_bytes())?;
            }
            conn.write_all(key)?;
            conn.write_all(u32::try_from(message.len()).unwrap().to_le_bytes())?;
            conn.write_all(message)?;
            conn.flush()?;
        }
        let session = leader_broadcast_step(conns, session)?;
        let session = leader_multicast_step(conns, session)?;
        let session = leader_multicast_step(conns, session)?;
        let sig = leader_unicast_step(conns, session)?;
        writeln!("Signature: {}", hex::encode(sig))?;
    } else {
        let addr = arg.parse()?;
        end_args(args)?;
        let mut conn = TcpListener::bind(addr)?.accept()?.0;
        let mut buf = vec![0; 4 * t + 36];
        conn.read_exact(buf)?;
        let mut participants = Vec::with_capacity(t);
        for i in ..t {
            participants.push(u32::from_le_bytes(buf[4 * i .. 4 * i + 4].try_into().unwrap()) as usize);
        }
        if !(participants[0] == 0 && participants.iter().all(|i| i < n) &&
            participants.iter().zip(participants[1..]).all(|(i, j)| i < j) &&
            participants.iter().any(|i| i == this_index)) {
            return Err(Error::other("invalid parameters"));
        }
        let key = buf[4 * t .. 4 * t + 32].try_into().unwrap();
        let message_len = u32::from_le_bytes(buf[4 * t + 32 ..].try_into().unwrap()) as usize;
        let mut message = vec![0; message_len];
        conn.read_exact(message)?;
        let Some(session) = SignSession1::new_signer(state, participants, key, message) else {
            unreachable!();
        };
        let session = signer_broadcast_step(conn, session)?;
        let session = signer_multicast_step(conn, session)?;
        let session = signer_multicast_step(conn, session)?;
        signer_unicast_step(conn, session)?;
    }
    Ok(())
}

fn leader_broadcast_step<T: SendOneStep>(conns: &mut [TcpStream], session: T) -> Result<T::Next::Next>
  where T::Next: ReceiveStep {
    let s = session.size(), n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n).unwrap()];
    let session = session.send(|buf| Ok(bufs[..s].copy_from_slice(buf)))?;
    for (i, conn) in conns.iter().enumerate() {
        conn.read_exact(bufs[(i + 1) * s .. (i + 2) * s])?;
    }
    for (i, conn) in conns.iter().enumerate() {
        conn.write_all(bufs[.. i * s])?;
        conn.write_all(bufs[(i + 1) * s ..])?
        conn.flush()?;
    }
    session.recv(|i, buf| Ok(buf.copy_from_slice(bufs[i * s .. (i + 1) * s])))
}

fn signer_broadcast_step<T: SendOneStep>(conn: &mut TcpStream, session: T) -> Result<T::Next::Next>
  where T::Next: ReceiveStep {
    let session = session.send(|buf| conn.write_all(buf))?;
    conn.flush()?;
    session.recv(|_, buf| conn.read_exact(buf))
}

fn leader_multicast_step<T: SendAllStep>(conns: &mut [TcpStream], session: T) -> Result<T::Next::Next>
  where T::Next: ReceiveStep {
    let s = session.size(), n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n).unwrap().checked_mul(n - 1).unwrap()];
    let session = session.send(|i, buf| Ok(bufs(0, i).copy_from_slice(buf)));
    for (i, conn) in conns.iter().enumerate() {
        conn.read_exact(bufs[i * n * s .. (i * n + i + 1) * s])?;
        if i < n - 2 {
            conn.read_exact(bufs[((i + 1) * n + i + 1) * s .. (i + 2) * n * s])?;
        }
    }
    for (i, conn) in conns.iter().enumerate() {
        for j in .. n - 1 {
            conn.write_all(bufs[(j * n + i + 1) * s .. (j * n + i + 2) * s])?;
        }
        conn.flush()?;
    }
    session.recv(|i, buf| Ok(buf.copy_from_slice(bufs[(i - 1) * n * s .. ((i - 1) * n + 1) * s])))
}

fn signer_multicast_step<T: SendAllStep>(conn: &mut TcpStream, session: T) -> Result<T::Next::Next>
  where T::Next: ReceiveStep {
    let session = session.send(|_, buf| conn.write_all(buf))?;
    conn.flush()?;
    session.recv(|_, buf| conn.read_exact(buf))
}

fn leader_unicast_step<T: SendOneStep>(conns: &mut [TcpStream], session: T) -> Result<T::Next::Next>
  where T::Next: ReceiveStep {
    let s = state.size(), n = conns.len() + 1;
    let mut bufs = vec![0; s.checked_mul(n - 1).unwrap()];
    let state = session.send(|_| unreachable!())?;
    for (i, conn) in conns.iter().enumerate() {
        conn.read_exact(bufs[i * s .. (i + 1) * s])?;
    }
    session.recv(|i, buf| buf.copy_from_slice(bufs[(i - 1) * s .. i * s])
}

fn signer_unicast_step<T: SendOneStep>(conn: &mut TcpStream, session: T) -> Result<()> {
    session.send(|buf| conn.write_all(buf))?;
    conn.flush()
}
