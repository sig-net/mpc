use redis_module::{Context, RedisError, RedisResult, RedisString, RedisValue};

/// Command: mpc.artifact.insert
/// Arguments: artifact_key owner_keys owner_key artifact_id artifact num_holders [holder...]
pub fn artifact_insert(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 6 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let owner_keys = args[2].to_string_lossy();
    let owner_key = args[3].to_string_lossy();
    let artifact_id = args[4].to_string_lossy();
    let artifact = args[5].to_string_lossy();

    ctx.call("SADD", &[&owner_key, &artifact_id])?;
    ctx.call("SADD", &[&owner_keys, &owner_key])?;
    ctx.call("HSET", &[&artifact_key, &artifact_id, &artifact])?;

    let holders_key = crate::keys::holders_key(&artifact_key, &artifact_id);
    ctx.call("DEL", &[&holders_key])?;

    for holder_arg in args.iter().skip(6) {
        let holder = holder_arg.to_string_lossy();
        ctx.call("SADD", &[&holders_key, &holder])?;
    }

    Ok(RedisValue::SimpleString("OK".to_string()))
}

/// Command: mpc.artifact.take
pub fn artifact_take(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 4 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let owner_key = args[2].to_string_lossy();
    let artifact_id = args[3].to_string_lossy();

    let removed = ctx.call("SREM", &[&owner_key, &artifact_id])?;
    if let RedisValue::Integer(0) = removed {
        return Err(RedisError::String(format!(
            "WARN artifact {} is not owned by this owner",
            artifact_id
        )));
    }

    let artifact = ctx.call("HGET", &[&artifact_key, &artifact_id])?;
    if let RedisValue::Null = artifact {
        return Err(RedisError::String(format!(
            "WARN artifact {} not found",
            artifact_id
        )));
    }

    ctx.call("HDEL", &[&artifact_key, &artifact_id])?;
    let holders_key = crate::keys::holders_key(&artifact_key, &artifact_id);
    let holders = ctx.call("SMEMBERS", &[&holders_key])?;
    ctx.call("DEL", &[&holders_key])?;

    let artifact_str = match artifact {
        RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s,
        _ => return Err(RedisError::String("artifact not a string".to_string())),
    };

    let holders_list = match holders {
        RedisValue::Array(arr) => arr,
        _ => return Err(RedisError::String("holders not an array".to_string())),
    };

    Ok(RedisValue::Array(vec![
        RedisValue::BulkString(artifact_str),
        RedisValue::Array(holders_list),
    ]))
}

/// Command: mpc.artifact.take_mine
pub fn artifact_take_mine(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let owner_key = args[2].to_string_lossy();

    let count_res = ctx.call("SCARD", &[&owner_key])?;
    if let RedisValue::Integer(0) = count_res {
        return Ok(RedisValue::Null);
    }

    let artifact_id_res = ctx.call("SPOP", &[&owner_key])?;
    let artifact_id_str = match &artifact_id_res {
        RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s.clone(),
        _ => return Ok(RedisValue::Null),
    };

    let artifact = ctx.call("HGET", &[&artifact_key, &artifact_id_str])?;
    if let RedisValue::Null = artifact {
        return Err(RedisError::String(format!(
            "WARN unexpected, artifact {} is missing",
            artifact_id_str
        )));
    }

    ctx.call("HDEL", &[&artifact_key, &artifact_id_str])?;
    let holders_key = crate::keys::holders_key(&artifact_key, &artifact_id_str);
    let holders = ctx.call("SMEMBERS", &[&holders_key])?;
    ctx.call("DEL", &[&holders_key])?;

    let artifact_str = match artifact {
        RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s,
        _ => return Err(RedisError::String("artifact not a string".to_string())),
    };

    let holders_list = match holders {
        RedisValue::Array(arr) => arr,
        _ => return Err(RedisError::String("holders not an array".to_string())),
    };

    Ok(RedisValue::Array(vec![
        RedisValue::BulkString(artifact_str),
        RedisValue::Array(holders_list),
    ]))
}

/// Command: mpc.artifact.contains
pub fn artifact_contains(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let artifact_id = args[2].to_string_lossy();

    let exists = ctx.call("HEXISTS", &[&artifact_key, &artifact_id])?;
    Ok(exists)
}

/// Command: mpc.artifact.contains_by_owner
pub fn artifact_contains_by_owner(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    let owner_key = args[1].to_string_lossy();
    let artifact_id = args[2].to_string_lossy();

    let exists = ctx.call("SISMEMBER", &[&owner_key, &artifact_id])?;
    Ok(exists)
}

/// Command: mpc.artifact.fetch_owned
pub fn artifact_fetch_owned(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let owner_key = args[1].to_string_lossy();
    let members = ctx.call("SMEMBERS", &[&owner_key])?;
    Ok(members)
}

/// Command: mpc.artifact.len_generated
pub fn artifact_len_generated(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let len_res = ctx.call("HLEN", &[&artifact_key])?;
    Ok(len_res)
}

/// Command: mpc.artifact.len_by_owner
pub fn artifact_len_by_owner(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let owner_key = args[1].to_string_lossy();
    let len_res = ctx.call("SCARD", &[&owner_key])?;
    Ok(len_res)
}

/// Command: mpc.artifact.remove_outdated
pub fn artifact_remove_outdated(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 3 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let owner_key = args[2].to_string_lossy();
    let owner_shares: Vec<String> = args[3..].iter().map(|s| s.to_string_lossy()).collect();

    let current_members_res = ctx.call("SMEMBERS", &[&owner_key])?;
    let current_members = match current_members_res {
        RedisValue::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s,
                _ => "".to_string(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let owner_shares_set: std::collections::HashSet<&String> = owner_shares.iter().collect();
    let outdated: Vec<String> = current_members
        .into_iter()
        .filter(|id| !owner_shares_set.contains(id))
        .collect();

    let mut not_found: Vec<RedisValue> = Vec::new();
    for id in &owner_shares {
        let exists = ctx.call("HEXISTS", &[&artifact_key, id])?;
        if let RedisValue::Integer(0) = exists {
            not_found.push(RedisValue::BulkString(id.clone()));
        }
    }

    let mut outdated_rvs: Vec<RedisValue> = Vec::new();
    for id in &outdated {
        ctx.call("SREM", &[&owner_key, id])?;
        ctx.call("HDEL", &[&artifact_key, id])?;
        let holders_key = crate::keys::holders_key(&artifact_key, id);
        ctx.call("DEL", &[&holders_key])?;
        outdated_rvs.push(RedisValue::BulkString(id.clone()));
    }

    Ok(RedisValue::Array(vec![
        RedisValue::Array(outdated_rvs),
        RedisValue::Array(not_found),
    ]))
}

/// Command: mpc.artifact.remove_holder_and_prune
pub fn artifact_remove_holder_and_prune(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 5 {
        return Err(RedisError::WrongArity);
    }

    let artifact_key = args[1].to_string_lossy();
    let owner_key = args[2].to_string_lossy();
    let peer = args[3].to_string_lossy();
    let threshold: usize = args[4].to_string_lossy().parse().unwrap_or(0);
    let artifact_ids: Vec<String> = args[5..].iter().map(|s| s.to_string_lossy()).collect();

    let mut removed: Vec<RedisValue> = Vec::new();
    let mut updated: Vec<RedisValue> = Vec::new();

    for artifact_id in &artifact_ids {
        let is_member = ctx.call("SISMEMBER", &[&owner_key, artifact_id])?;
        if let RedisValue::Integer(0) = is_member {
            continue;
        }

        let holders_key = crate::keys::holders_key(&artifact_key, artifact_id);
        let exists = ctx.call("EXISTS", &[&holders_key])?;
        if let RedisValue::Integer(0) = exists {
            continue;
        }

        ctx.call("SREM", &[&holders_key, &peer])?;
        let count_res = ctx.call("SCARD", &[&holders_key])?;
        let count: usize = match count_res {
            RedisValue::Integer(c) => c as usize,
            _ => 0,
        };

        if count < threshold {
            ctx.call("HDEL", &[&artifact_key, artifact_id])?;
            ctx.call("DEL", &[&holders_key])?;
            ctx.call("SREM", &[&owner_key, artifact_id])?;
            removed.push(RedisValue::BulkString(artifact_id.clone()));
        } else {
            updated.push(RedisValue::BulkString(artifact_id.clone()));
        }
    }

    Ok(RedisValue::Array(vec![
        RedisValue::Array(removed),
        RedisValue::Array(updated),
    ]))
}

/// Command: mpc.artifact.clear
pub fn artifact_clear(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    let owner_keys = args[1].to_string_lossy();
    let artifact_key = args[2].to_string_lossy();

    let owner_keys_list_res = ctx.call("SMEMBERS", &[&owner_keys])?;
    let owner_keys_list = match owner_keys_list_res {
        RedisValue::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s,
                _ => "".to_string(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let artifact_ids_res = ctx.call("HKEYS", &[&artifact_key])?;
    let artifact_ids = match artifact_ids_res {
        RedisValue::Array(arr) => arr
            .into_iter()
            .map(|v| match v {
                RedisValue::SimpleString(s) | RedisValue::BulkString(s) => s,
                _ => "".to_string(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let mut keys_to_delete: Vec<String> = Vec::new();
    keys_to_delete.push(owner_keys.clone());
    keys_to_delete.push(artifact_key.clone());
    keys_to_delete.extend(owner_keys_list);

    for artifact_id in &artifact_ids {
        let holders_key = crate::keys::holders_key(&artifact_key, artifact_id);
        keys_to_delete.push(holders_key);
    }

    for key in &keys_to_delete {
        ctx.call("DEL", &[key])?;
    }

    Ok(RedisValue::SimpleString("OK".to_string()))
}
