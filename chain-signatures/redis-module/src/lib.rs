use redis_module::{Context, RedisError, RedisResult, RedisString, RedisValue};
use mpc_node::protocol::triple::{Triple, TripleId};
use mpc_node::protocol::presignature::{Presignature, PresignatureId};
use cait_sith::protocol::Participant;
use near_account_id::AccountId;
use serde_json;

const STORAGE_VERSION: &str = "1";

fn get_triple_key(account_id: &AccountId) -> String {
    format!("triples:{STORAGE_VERSION}:{account_id}")
}

fn get_used_triple_key(account_id: &AccountId) -> String {
    format!("triples_used:{STORAGE_VERSION}:{account_id}")
}

fn get_reserved_triple_key(account_id: &AccountId) -> String {
    format!("triples_reserved:{STORAGE_VERSION}:{account_id}")
}

fn get_owner_keys_triple(account_id: &AccountId) -> String {
    format!("triples_owners:{STORAGE_VERSION}:{account_id}")
}

fn get_owner_key_triple(owner_keys: &str, owner: Participant) -> String {
    format!("{owner_keys}:p{}", Into::<u32>::into(owner))
}

fn get_presig_key(account_id: &AccountId) -> String {
    format!("presignatures:{STORAGE_VERSION}:{account_id}")
}

fn get_used_presig_key(account_id: &AccountId) -> String {
    format!("presignatures_used:{STORAGE_VERSION}:{account_id}")
}

fn get_reserved_presig_key(account_id: &AccountId) -> String {
    format!("presignatures_reserved:{STORAGE_VERSION}:{account_id}")
}

fn get_owner_keys_presig(account_id: &AccountId) -> String {
    format!("presignatures_owners:{STORAGE_VERSION}:{account_id}")
}

fn get_owner_key_presig(owner_keys: &str, owner: Participant) -> String {
    format!("{owner_keys}:p{}", Into::<u32>::into(owner))
}

// Placeholder implementations - will be implemented in next steps
fn triples_reserve(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::String("ERR wrong number of arguments for 'TRIPLES.RESERVE' command".to_string()));
    }

    let account_id: AccountId = match args[0].to_string().parse() {
        Ok(id) => id,
        Err(_) => return Err(RedisError::String("ERR invalid account_id".to_string())),
    };

    let triple_id: TripleId = match args[1].to_string().parse() {
        Ok(id) => id,
        Err(_) => return Err(RedisError::String("ERR invalid triple_id".to_string())),
    };

    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let reserved_key = get_reserved_triple_key(&account_id);

    let triple_key_rs = ctx.create_string(triple_key.as_str());
    let used_key_rs = ctx.create_string(used_key.as_str());
    let reserved_key_rs = ctx.create_string(reserved_key.as_str());
    let triple_id_rs = ctx.create_string(triple_id.to_string().as_str());

    // Check if already reserved
    match ctx.call("SADD", &[&reserved_key_rs, &triple_id_rs]) {
        Ok(RedisValue::Integer(0)) => return Err(RedisError::String(format!("WARN triple {} has already been reserved", triple_id))),
        Ok(RedisValue::Integer(_)) => {},
        Ok(_) => return Err(RedisError::String("ERR unexpected response from SADD".to_string())),
        Err(e) => return Err(e),
    }

    // Check if already stored
    match ctx.call("HEXISTS", &[&triple_key_rs, &triple_id_rs]) {
        Ok(RedisValue::Integer(1)) => return Err(RedisError::String(format!("WARN triple {} has already been stored", triple_id))),
        Ok(RedisValue::Integer(0)) => {},
        Ok(_) => return Err(RedisError::String("ERR unexpected response from HEXISTS".to_string())),
        Err(e) => return Err(e),
    }

    // Check if already used
    match ctx.call("HEXISTS", &[&used_key_rs, &triple_id_rs]) {
        Ok(RedisValue::Integer(1)) => return Err(RedisError::String(format!("WARN triple {} has already been used", triple_id))),
        Ok(RedisValue::Integer(0)) => {},
        Ok(_) => return Err(RedisError::String("ERR unexpected response from HEXISTS".to_string())),
        Err(e) => return Err(e),
    }

    Ok(RedisValue::SimpleString("OK".to_string()))
}

fn triples_unreserve(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::SimpleString("OK".to_string()))
}

fn triples_remove_outdated(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::Array(vec![]))
}

fn triples_insert(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 4 {
        return Err(RedisError::String("ERR wrong number of arguments for 'triples_insert' command".to_string()));
    }

    let account_id: AccountId = args[0].to_string().parse().map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let triple_id: TripleId = args[1].to_string().parse().map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))?;
    let owner: Participant = Participant::from(args[2].to_string().parse::<u32>().map_err(|_| RedisError::String("ERR invalid owner".to_string()))?);
    let triple_json = args[3].to_string();

    let account_id_str = ctx.create_string(account_id.to_string());
    let triple_id_str = ctx.create_string(triple_id.to_string());
    let triple_json_str = ctx.create_string(triple_json);

    let reserved_key = get_reserved_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let triple_key = get_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let owner_key = get_owner_key_triple(&owner_keys, owner);

    let removed: RedisValue = ctx.call("SREM", &[&ctx.create_string(reserved_key), &triple_id_str])?;
    if let RedisValue::Integer(0) = removed {
        return Err(RedisError::String(format!("WARN triple {} has NOT been reserved", triple_id)));
    }

    let exists: RedisValue = ctx.call("HEXISTS", &[&ctx.create_string(used_key), &triple_id_str])?;
    if let RedisValue::Integer(1) = exists {
        return Err(RedisError::String(format!("WARN triple {} has already been used", triple_id)));
    }

    ctx.call("SADD", &[&ctx.create_string(owner_key.clone()), &triple_id_str])?;
    ctx.call("SADD", &[&ctx.create_string(owner_keys), &ctx.create_string(owner_key)])?;
    ctx.call("HSET", &[&ctx.create_string(triple_key), &triple_id_str, &triple_json_str])?;

    Ok(().into())
}

fn triples_take_two(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 5 {
        return Err(RedisError::String("ERR wrong number of arguments for 'triples_take_two' command".to_string()));
    }

    let account_id: AccountId = args[0].to_string().parse().map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let id1: TripleId = args[1].to_string().parse().map_err(|_| RedisError::String("ERR invalid id1".to_string()))?;
    let id2: TripleId = args[2].to_string().parse().map_err(|_| RedisError::String("ERR invalid id2".to_string()))?;
    let owner: Participant = Participant::from(args[3].to_string().parse::<u32>().map_err(|_| RedisError::String("ERR invalid owner".to_string()))?);
    let me: Participant = Participant::from(args[4].to_string().parse::<u32>().map_err(|_| RedisError::String("ERR invalid me".to_string()))?);

    let id1_str = ctx.create_string(id1.to_string());
    let id2_str = ctx.create_string(id2.to_string());

    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let owner_key = get_owner_key_triple(&owner_keys, owner);
    let mine_key = get_owner_key_triple(&owner_keys, me);
    let reserved_key = get_reserved_triple_key(&account_id);

    let reserved: RedisValue = ctx.call("SMISMEMBER", &[&ctx.create_string(reserved_key), &id1_str, &id2_str])?;
    if let RedisValue::Array(arr) = &reserved {
        if arr.len() >= 2 {
            if let RedisValue::Integer(1) = &arr[0] {
                return Err(RedisError::String(format!("WARN triple {} or {} is generating or taken", id1, id2)));
            }
            if let RedisValue::Integer(1) = &arr[1] {
                return Err(RedisError::String(format!("WARN triple {} or {} is generating or taken", id1, id2)));
            }
        }
    }

    let mine_check: RedisValue = ctx.call("SMISMEMBER", &[&ctx.create_string(mine_key), &id1_str, &id2_str])?;
    if let RedisValue::Array(arr) = &mine_check {
        if arr.len() >= 2 {
            if let RedisValue::Integer(1) = &arr[0] {
                return Err(RedisError::String(format!("WARN triple {} or {} cannot be taken as foreign owned", id1, id2)));
            }
            if let RedisValue::Integer(1) = &arr[1] {
                return Err(RedisError::String(format!("WARN triple {} or {} cannot be taken as foreign owned", id1, id2)));
            }
        }
    }

    let owner_check: RedisValue = ctx.call("SMISMEMBER", &[&ctx.create_string(owner_key.clone()), &id1_str, &id2_str])?;
    if let RedisValue::Array(arr) = &owner_check {
        if arr.len() >= 2 {
            if let RedisValue::Integer(0) = &arr[0] {
                return Err(RedisError::String(format!("WARN triple {} or {} cannot be taken by incorrect owner {}", id1, id2, owner_key)));
            }
            if let RedisValue::Integer(0) = &arr[1] {
                return Err(RedisError::String(format!("WARN triple {} or {} cannot be taken by incorrect owner {}", id1, id2, owner_key)));
            }
        }
    }

    let triples: RedisValue = ctx.call("HMGET", &[&ctx.create_string(triple_key.clone()), &id1_str, &id2_str])?;
    if let RedisValue::Array(arr) = &triples {
        if arr.len() >= 2 {
            if let RedisValue::Null = &arr[0] {
                return Err(RedisError::String(format!("WARN unexpected, triple {} is missing", id1)));
            }
            if let RedisValue::Null = &arr[1] {
                return Err(RedisError::String(format!("WARN unexpected, triple {} is missing", id2)));
            }
        }
    }

    ctx.call("HDEL", &[&ctx.create_string(triple_key), &id1_str, &id2_str])?;
    ctx.call("SREM", &[&ctx.create_string(owner_key), &id1_str, &id2_str])?;
    ctx.call("HSET", &[&ctx.create_string(used_key.clone()), &id1_str, &ctx.create_string("1"), &id2_str, &ctx.create_string("1")])?;
    ctx.call("HEXPIRE", &[&ctx.create_string(used_key), &ctx.create_string("86400"), &ctx.create_string("FIELDS"), &ctx.create_string("2"), &id1_str, &id2_str])?;

    Ok(triples)
}

fn triples_clear(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 1 {
        return Err(RedisError::String("ERR wrong number of arguments for 'triples_clear' command".to_string()));
    }

    let account_id: AccountId = args[0].to_string().parse().map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;

    let owner_keys = get_owner_keys_triple(&account_id);
    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let reserved_key = get_reserved_triple_key(&account_id);

    let owner_keys_list: RedisValue = ctx.call("SMEMBERS", &[&ctx.create_string(owner_keys.clone())])?;
    let mut del_keys = vec![
        ctx.create_string(owner_keys),
        ctx.create_string(triple_key),
        ctx.create_string(used_key),
        ctx.create_string(reserved_key),
    ];

    if let RedisValue::Array(arr) = owner_keys_list {
        for key in arr {
            if let RedisValue::SimpleString(s) = key {
                del_keys.push(ctx.create_string(s));
            }
        }
    }

    let del_refs: Vec<&RedisString> = del_keys.iter().collect();
    ctx.call("DEL", &del_refs[..])?;

    Ok(().into())
}

fn presig_reserve(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::SimpleString("OK".to_string()))
}

fn presig_unreserve(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::SimpleString("OK".to_string()))
}

fn presig_remove_outdated(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::Array(vec![]))
}

fn presig_insert(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::SimpleString("OK".to_string()))
}

fn presig_take(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::Null)
}

fn presig_take_mine(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::Null)
}

fn presig_clear(_ctx: &Context, _args: Vec<RedisString>) -> RedisResult {
    Ok(RedisValue::SimpleString("OK".to_string()))
}

redis_module::redis_module! {
    name: "mpc_redis_module",
    version: 1,
    allocator: (redis_module::alloc::RedisAlloc, redis_module::alloc::RedisAlloc),
    data_types: [],
    commands: [
        ["triples.reserve", triples_reserve, "write", 0, 0, 0],
        ["triples.insert", triples_insert, "write", 0, 0, 0],
        ["triples.take_two", triples_take_two, "write", 0, 0, 0],
        ["triples.clear", triples_clear, "write", 0, 0, 0],
    ],
}