use cait_sith::protocol::Participant;
use mpc_node::protocol::presignature::PresignatureId;
use mpc_node::protocol::triple::TripleId;
use near_account_id::AccountId;
use redis_module::{Context, RedisError, RedisResult, RedisString, RedisValue};

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

pub extern "C" fn test_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 0 {
        return Err(RedisError::String(format!(
            "ERR wrong number of arguments for 'test' command, got {}",
            args.len()
        )));
    }

    Ok(RedisValue::SimpleString("OK".to_string()))
}

extern "C" fn triples_reserve(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::String(format!(
            "ERR DEBUG: wrong number of arguments for 'triples_reserve' command, expected 3, got {}",
            args.len()
        )));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let triple_id: TripleId = args[2]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))?;

    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let reserved_key = get_reserved_triple_key(&account_id);

    // Check if already reserved
    let reserved_key_rs = ctx.create_string(reserved_key.as_str());
    let is_reserved = ctx.call(
        "SISMEMBER",
        &[
            &reserved_key_rs,
            &ctx.create_string(triple_id.to_string().as_str()),
        ],
    )?;
    if let RedisValue::Integer(1) = is_reserved {
        return Err(RedisError::String(format!(
            "ERR triple {} already reserved",
            triple_id
        )));
    }

    // Check if already used
    let used_key_rs = ctx.create_string(used_key.as_str());
    let is_used = ctx.call(
        "HEXISTS",
        &[
            &used_key_rs,
            &ctx.create_string(triple_id.to_string().as_str()),
        ],
    )?;
    if let RedisValue::Integer(1) = is_used {
        return Err(RedisError::String(format!(
            "ERR triple {} already used",
            triple_id
        )));
    }

    // Reserve it
    ctx.call(
        "SADD",
        &[
            &reserved_key_rs,
            &ctx.create_string(triple_id.to_string().as_str()),
        ],
    )?;

    Ok(RedisValue::SimpleString(triple_id.to_string()))
}

pub extern "C" fn triples_unreserve(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'triples_unreserve' command".to_string(),
        ));
    }

    let account_id: AccountId = args[0]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let triple_ids: Vec<TripleId> = args[1..]
        .iter()
        .map(|s| {
            s.to_string()
                .parse()
                .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let reserved_key = get_reserved_triple_key(&account_id);
    let mut srem_args = vec![ctx.create_string(reserved_key)];
    for id in &triple_ids {
        srem_args.push(ctx.create_string(id.to_string()));
    }

    let srem_refs: Vec<&RedisString> = srem_args.iter().collect();
    ctx.call("SREM", &srem_refs[..])?;

    Ok(().into())
}

extern "C" fn triples_remove_outdated(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'triples_remove_outdated' command".to_string(),
        ));
    }

    let account_id: AccountId = args[0]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[1]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let owner_shares: Vec<TripleId> = args[2..]
        .iter()
        .map(|s| {
            s.to_string()
                .parse()
                .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let triple_key = get_triple_key(&account_id);
    let reserved_key = get_reserved_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let owner_key = get_owner_key_triple(&owner_keys, owner);

    let our_shares: RedisValue = ctx.call("SMEMBERS", &[&ctx.create_string(owner_key.clone())])?;
    let mut outdated = Vec::new();

    if let RedisValue::Array(shares) = our_shares {
        let owner_shares_set: std::collections::HashSet<String> =
            owner_shares.iter().map(|id| id.to_string()).collect();
        for share in shares {
            if let RedisValue::SimpleString(id_str) = share {
                if !owner_shares_set.contains(&id_str) {
                    outdated.push(id_str);
                }
            }
        }
    }

    if !outdated.is_empty() {
        // SREM owner_key
        let mut srem_owner_args = vec![ctx.create_string(owner_key.clone())];
        for id in &outdated {
            srem_owner_args.push(ctx.create_string(id.clone()));
        }
        let srem_owner_refs: Vec<&RedisString> = srem_owner_args.iter().collect();
        ctx.call("SREM", &srem_owner_refs[..])?;

        // SREM reserved_key
        let mut srem_reserved_args = vec![ctx.create_string(reserved_key)];
        for id in &outdated {
            srem_reserved_args.push(ctx.create_string(id.clone()));
        }
        let srem_reserved_refs: Vec<&RedisString> = srem_reserved_args.iter().collect();
        ctx.call("SREM", &srem_reserved_refs[..])?;

        // HDEL triple_key
        let mut hdel_args = vec![ctx.create_string(triple_key)];
        for id in &outdated {
            hdel_args.push(ctx.create_string(id.clone()));
        }
        let hdel_refs: Vec<&RedisString> = hdel_args.iter().collect();
        ctx.call("HDEL", &hdel_refs[..])?;
    }

    let outdated_values: Vec<RedisValue> = outdated
        .into_iter()
        .map(|s| RedisValue::SimpleString(s))
        .collect();
    Ok(RedisValue::Array(outdated_values))
}

extern "C" fn triples_insert(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 5 {
        return Err(RedisError::String(format!(
            "ERR wrong number of arguments for 'triples_insert' command, got {}",
            args.len()
        )));
    }

    let account_id_str = args[1].to_string();
    let account_id: AccountId = account_id_str.parse().map_err(|_| {
        RedisError::String(format!(
            "ERR DEBUG invalid account_id: '{}'",
            account_id_str
        ))
    })?;
    let triple_id: TripleId = args[2]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[4]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let triple_json = args[3].to_string();

    let _account_id_str = ctx.create_string(account_id.to_string());
    let triple_id_str = ctx.create_string(triple_id.to_string());
    let triple_json_str = ctx.create_string(triple_json);

    let reserved_key = get_reserved_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let triple_key = get_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let owner_key = get_owner_key_triple(&owner_keys, owner);

    let removed: RedisValue =
        ctx.call("SREM", &[&ctx.create_string(reserved_key), &triple_id_str])?;
    if let RedisValue::Integer(0) = removed {
        return Err(RedisError::String(format!(
            "WARN triple {} has NOT been reserved",
            triple_id
        )));
    }

    let exists: RedisValue =
        ctx.call("HEXISTS", &[&ctx.create_string(used_key), &triple_id_str])?;
    if let RedisValue::Integer(1) = exists {
        return Err(RedisError::String(format!(
            "WARN triple {} has already been used",
            triple_id
        )));
    }

    ctx.call(
        "SADD",
        &[&ctx.create_string(owner_key.clone()), &triple_id_str],
    )?;
    ctx.call(
        "SADD",
        &[
            &ctx.create_string(owner_keys),
            &ctx.create_string(owner_key),
        ],
    )?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(triple_key),
            &triple_id_str,
            &triple_json_str,
        ],
    )?;

    Ok(RedisValue::SimpleString("INSERTED".to_string()))
}

extern "C" fn triples_take_two(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 6 {
        return Err(RedisError::String(format!(
            "ERR wrong number of arguments for 'triples_take_two' command, got {}",
            args.len()
        )));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let id1: TripleId = args[2]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))?;
    let id2: TripleId = args[3]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid triple_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[4]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let me: Participant = Participant::from(
        args[5]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid me".to_string()))?,
    );

    let id1_str = ctx.create_string(id1.to_string());
    let id2_str = ctx.create_string(id2.to_string());

    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let owner_key = get_owner_key_triple(&owner_keys, owner);
    let mine_key = get_owner_key_triple(&owner_keys, me);
    let reserved_key = get_reserved_triple_key(&account_id);

    let reserved: RedisValue = ctx.call(
        "SMISMEMBER",
        &[&ctx.create_string(reserved_key), &id1_str, &id2_str],
    )?;
    if let RedisValue::Array(arr) = &reserved {
        if arr.len() >= 2 {
            if let RedisValue::Integer(1) = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} is generating or taken",
                    id1, id2
                )));
            }
            if let RedisValue::Integer(1) = &arr[1] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} is generating or taken",
                    id1, id2
                )));
            }
        }
    }

    let mine_check: RedisValue = ctx.call(
        "SMISMEMBER",
        &[&ctx.create_string(mine_key), &id1_str, &id2_str],
    )?;
    if let RedisValue::Array(arr) = &mine_check {
        if arr.len() >= 2 {
            if let RedisValue::Integer(1) = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} cannot be taken as foreign owned",
                    id1, id2
                )));
            }
            if let RedisValue::Integer(1) = &arr[1] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} cannot be taken as foreign owned",
                    id1, id2
                )));
            }
        }
    }

    let owner_check: RedisValue = ctx.call(
        "SMISMEMBER",
        &[&ctx.create_string(owner_key.clone()), &id1_str, &id2_str],
    )?;
    if let RedisValue::Array(arr) = &owner_check {
        if arr.len() >= 2 {
            if let RedisValue::Integer(0) = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} cannot be taken by incorrect owner {}",
                    id1, id2, owner_key
                )));
            }
            if let RedisValue::Integer(0) = &arr[1] {
                return Err(RedisError::String(format!(
                    "WARN triple {} or {} cannot be taken by incorrect owner {}",
                    id1, id2, owner_key
                )));
            }
        }
    }

    let triples: RedisValue = ctx.call(
        "HMGET",
        &[&ctx.create_string(triple_key.clone()), &id1_str, &id2_str],
    )?;
    if let RedisValue::Array(arr) = &triples {
        if arr.len() >= 2 {
            if let RedisValue::Null = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN unexpected, triple {} is missing",
                    id1
                )));
            }
            if let RedisValue::Null = &arr[1] {
                return Err(RedisError::String(format!(
                    "WARN unexpected, triple {} is missing",
                    id2
                )));
            }
        }
    }

    ctx.call(
        "HDEL",
        &[&ctx.create_string(triple_key), &id1_str, &id2_str],
    )?;
    ctx.call("SREM", &[&ctx.create_string(owner_key), &id1_str, &id2_str])?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(used_key.clone()),
            &id1_str,
            &ctx.create_string("1"),
            &id2_str,
            &ctx.create_string("1"),
        ],
    )?;
    ctx.call(
        "HEXPIRE",
        &[
            &ctx.create_string(used_key),
            &ctx.create_string("86400"),
            &ctx.create_string("FIELDS"),
            &ctx.create_string("2"),
            &id1_str,
            &id2_str,
        ],
    )?;

    Ok(triples)
}

extern "C" fn triples_take_two_mine(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'triples_take_two_mine' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let me: Participant = Participant::from(
        args[2]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid me".to_string()))?,
    );

    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let owner_keys = get_owner_keys_triple(&account_id);
    let mine_key = get_owner_key_triple(&owner_keys, me);
    let reserved_key = get_reserved_triple_key(&account_id);

    let card: RedisValue = ctx.call("SCARD", &[&ctx.create_string(mine_key.clone())])?;
    if let RedisValue::Integer(count) = card {
        if count < 2 {
            return Ok(RedisValue::Null);
        }
    }

    let triple_ids: RedisValue = ctx.call(
        "SPOP",
        &[
            &ctx.create_string(mine_key.clone()),
            &ctx.create_string("2"),
        ],
    )?;
    let ids = if let RedisValue::Array(arr) = &triple_ids {
        arr.clone()
    } else {
        return Ok(RedisValue::Null);
    };

    if ids.len() < 2 {
        return Ok(RedisValue::Null);
    }

    let id1 = if let RedisValue::SimpleString(s) = &ids[0] {
        s.clone()
    } else {
        return Ok(RedisValue::Null);
    };
    let id2 = if let RedisValue::SimpleString(s) = &ids[1] {
        s.clone()
    } else {
        return Ok(RedisValue::Null);
    };

    let triples: RedisValue = ctx.call(
        "HMGET",
        &[
            &ctx.create_string(triple_key.clone()),
            &ctx.create_string(id1.clone()),
            &ctx.create_string(id2.clone()),
        ],
    )?;
    if let RedisValue::Array(arr) = &triples {
        if arr.len() >= 2 {
            if let RedisValue::Null = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN unexpected, triple {} is missing",
                    id1
                )));
            }
            if let RedisValue::Null = &arr[1] {
                return Err(RedisError::String(format!(
                    "WARN unexpected, triple {} is missing",
                    id2
                )));
            }
        }
    }

    ctx.call(
        "SADD",
        &[
            &ctx.create_string(reserved_key),
            &ctx.create_string(id1.clone()),
            &ctx.create_string(id2.clone()),
        ],
    )?;
    ctx.call(
        "HDEL",
        &[
            &ctx.create_string(triple_key),
            &ctx.create_string(id1.clone()),
            &ctx.create_string(id2.clone()),
        ],
    )?;
    ctx.call(
        "SREM",
        &[
            &ctx.create_string(mine_key),
            &ctx.create_string(id1.clone()),
            &ctx.create_string(id2.clone()),
        ],
    )?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(used_key.clone()),
            &ctx.create_string(id1.clone()),
            &ctx.create_string("1"),
            &ctx.create_string(id2.clone()),
            &ctx.create_string("1"),
        ],
    )?;
    ctx.call(
        "HEXPIRE",
        &[
            &ctx.create_string(used_key),
            &ctx.create_string("86400"),
            &ctx.create_string("FIELDS"),
            &ctx.create_string("2"),
            &ctx.create_string(id1),
            &ctx.create_string(id2),
        ],
    )?;

    Ok(triples)
}

extern "C" fn triples_clear(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'triples_clear' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;

    let owner_keys = get_owner_keys_triple(&account_id);
    let triple_key = get_triple_key(&account_id);
    let used_key = get_used_triple_key(&account_id);
    let reserved_key = get_reserved_triple_key(&account_id);

    let owner_keys_list: RedisValue =
        ctx.call("SMEMBERS", &[&ctx.create_string(owner_keys.clone())])?;
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

extern "C" fn presig_reserve(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_reserve' command".to_string(),
        ));
    }

    let account_id: AccountId = match args[1].to_string().parse() {
        Ok(id) => id,
        Err(_) => return Err(RedisError::String("ERR invalid account_id".to_string())),
    };

    let owner: Participant = match args[2].to_string().parse::<u32>() {
        Ok(id) => Participant::from(id),
        Err(_) => return Err(RedisError::String("ERR invalid owner".to_string())),
    };

    let presig_key = get_presig_key(&account_id);
    let used_key = get_used_presig_key(&account_id);
    let reserved_key = get_reserved_presig_key(&account_id);
    let owner_keys = get_owner_keys_presig(&account_id);
    let owner_key = get_owner_key_presig(&owner_keys, owner);

    let presig_key_rs = ctx.create_string(presig_key.as_str());
    let used_key_rs = ctx.create_string(used_key.as_str());
    let reserved_key_rs = ctx.create_string(reserved_key.as_str());
    let owner_keys_rs = ctx.create_string(owner_keys.as_str());
    let owner_key_rs = ctx.create_string(owner_key.as_str());

    // Get a random available presignature
    let our_presigs: RedisValue =
        ctx.call("SRANDMEMBER", &[&presig_key_rs, &ctx.create_string("1")])?;
    let presig_id_str = match our_presigs {
        RedisValue::Array(arr) if arr.len() == 1 => match &arr[0] {
            RedisValue::SimpleString(s) => s.clone(),
            _ => {
                return Err(RedisError::String(
                    "ERR unexpected response from SRANDMEMBER".to_string(),
                ))
            }
        },
        _ => {
            return Err(RedisError::String(
                "ERR no available presignatures".to_string(),
            ))
        }
    };

    let presig_id: PresignatureId = match presig_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return Err(RedisError::String(
                "ERR invalid presig_id from SRANDMEMBER".to_string(),
            ))
        }
    };

    let presig_id_rs = ctx.create_string(presig_id.to_string().as_str());

    // Check if already reserved
    match ctx.call("SISMEMBER", &[&reserved_key_rs, &presig_id_rs]) {
        Ok(RedisValue::Integer(1)) => {
            return Err(RedisError::String(format!(
                "WARN presignature {} has already been reserved",
                presig_id
            )))
        }
        Ok(RedisValue::Integer(0)) => {}
        Ok(_) => {
            return Err(RedisError::String(
                "ERR unexpected response from SISMEMBER".to_string(),
            ))
        }
        Err(e) => return Err(e),
    }

    // Check if already used
    match ctx.call("HEXISTS", &[&used_key_rs, &presig_id_rs]) {
        Ok(RedisValue::Integer(1)) => {
            return Err(RedisError::String(format!(
                "WARN presignature {} has already been used",
                presig_id
            )))
        }
        Ok(RedisValue::Integer(0)) => {}
        Ok(_) => {
            return Err(RedisError::String(
                "ERR unexpected response from HEXISTS".to_string(),
            ))
        }
        Err(e) => return Err(e),
    }

    // Reserve it
    match ctx.call("SADD", &[&reserved_key_rs, &presig_id_rs]) {
        Ok(RedisValue::Integer(_)) => {}
        Ok(_) => {
            return Err(RedisError::String(
                "ERR unexpected response from SADD".to_string(),
            ))
        }
        Err(e) => return Err(e),
    }

    // Assign to owner
    ctx.call("SADD", &[&owner_key_rs, &presig_id_rs])?;
    ctx.call("SADD", &[&owner_keys_rs, &owner_key_rs])?;

    Ok(RedisValue::SimpleString("OK".to_string()))
}

extern "C" fn presig_take_mine(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_take_mine' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let me: Participant = Participant::from(
        args[2]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid me".to_string()))?,
    );

    let presig_key = get_presig_key(&account_id);
    let used_key = get_used_presig_key(&account_id);
    let reserved_key = get_reserved_presig_key(&account_id);
    let owner_keys = get_owner_keys_presig(&account_id);
    let mine_key = get_owner_key_presig(&owner_keys, me);

    let presig_id: RedisValue = ctx.call("SPOP", &[&ctx.create_string(mine_key.clone())])?;
    let id_str = if let RedisValue::SimpleString(s) = presig_id {
        s
    } else {
        return Ok(RedisValue::Null);
    };

    let presig: RedisValue = ctx.call(
        "HGET",
        &[
            &ctx.create_string(presig_key.clone()),
            &ctx.create_string(id_str.clone()),
        ],
    )?;
    if let RedisValue::Null = presig {
        return Err(RedisError::String(format!(
            "WARN unexpected, presignature {} is missing",
            id_str
        )));
    }

    ctx.call(
        "SADD",
        &[
            &ctx.create_string(reserved_key),
            &ctx.create_string(id_str.clone()),
        ],
    )?;
    ctx.call(
        "HDEL",
        &[
            &ctx.create_string(presig_key),
            &ctx.create_string(id_str.clone()),
        ],
    )?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(used_key.clone()),
            &ctx.create_string(id_str.clone()),
            &ctx.create_string("1"),
        ],
    )?;
    ctx.call(
        "HEXPIRE",
        &[
            &ctx.create_string(used_key),
            &ctx.create_string("86400"),
            &ctx.create_string("FIELDS"),
            &ctx.create_string("1"),
            &ctx.create_string(id_str),
        ],
    )?;

    Ok(presig)
}

extern "C" fn presig_unreserve(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_unreserve' command".to_string(),
        ));
    }

    let account_id: AccountId = args[0]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let presig_ids: Vec<String> = args[1..].iter().map(|s| s.to_string()).collect();

    let reserved_key = get_reserved_presig_key(&account_id);

    let mut srem_args = vec![ctx.create_string(reserved_key)];
    for id in presig_ids {
        srem_args.push(ctx.create_string(id));
    }
    let srem_refs: Vec<&RedisString> = srem_args.iter().collect();
    ctx.call("SREM", &*srem_refs)?;

    Ok(().into())
}

extern "C" fn presig_insert(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 5 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_insert' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let presig_id: PresignatureId = args[2]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid presig_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[4]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let presig_json = args[3].to_string();

    let presig_id_str = ctx.create_string(presig_id.to_string());
    let presig_json_str = ctx.create_string(presig_json);

    let presig_key = get_presig_key(&account_id);
    let used_key = get_used_presig_key(&account_id);
    let reserved_key = get_reserved_presig_key(&account_id);
    let owner_keys = get_owner_keys_presig(&account_id);
    let owner_key = get_owner_key_presig(&owner_keys, owner);

    let removed: RedisValue =
        ctx.call("SREM", &[&ctx.create_string(reserved_key), &presig_id_str])?;
    if let RedisValue::Integer(0) = removed {
        return Err(RedisError::String(format!(
            "WARN presignature {} has NOT been reserved",
            presig_id
        )));
    }

    let exists: RedisValue =
        ctx.call("HEXISTS", &[&ctx.create_string(used_key), &presig_id_str])?;
    if let RedisValue::Integer(1) = exists {
        return Err(RedisError::String(format!(
            "WARN presignature {} is already used",
            presig_id
        )));
    }

    ctx.call(
        "SADD",
        &[&ctx.create_string(owner_key.clone()), &presig_id_str],
    )?;
    ctx.call(
        "SADD",
        &[
            &ctx.create_string(owner_keys),
            &ctx.create_string(owner_key),
        ],
    )?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(presig_key),
            &presig_id_str,
            &presig_json_str,
        ],
    )?;

    Ok(().into())
}

extern "C" fn presig_take(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 5 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_take' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let presig_id: PresignatureId = args[2]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid presig_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[3]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let me: Participant = Participant::from(
        args[4]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid me".to_string()))?,
    );

    let presig_id_str = ctx.create_string(presig_id.to_string());

    let presig_key = get_presig_key(&account_id);
    let used_key = get_used_presig_key(&account_id);
    let owner_keys = get_owner_keys_presig(&account_id);
    let owner_key = get_owner_key_presig(&owner_keys, owner);
    let mine_key = get_owner_key_presig(&owner_keys, me);
    let reserved_key = get_reserved_presig_key(&account_id);

    let reserved_check: RedisValue = ctx.call(
        "SMISMEMBER",
        &[&ctx.create_string(reserved_key), &presig_id_str],
    )?;
    if let RedisValue::Array(arr) = &reserved_check {
        if arr.len() >= 1 {
            if let RedisValue::Integer(1) = &arr[0] {
                return Err(RedisError::String(format!(
                    "WARN presignature {} is generating or taken",
                    presig_id
                )));
            }
        }
    }

    let mine_check: RedisValue =
        ctx.call("SISMEMBER", &[&ctx.create_string(mine_key), &presig_id_str])?;
    if let RedisValue::Integer(1) = mine_check {
        return Err(RedisError::String(format!(
            "WARN presignature {} cannot be taken as foreign owned",
            presig_id
        )));
    }

    let owner_check: RedisValue = ctx.call(
        "SISMEMBER",
        &[&ctx.create_string(owner_key.clone()), &presig_id_str],
    )?;
    if let RedisValue::Integer(0) = owner_check {
        return Err(RedisError::String(format!(
            "WARN presignature {} cannot be taken by incorrect owner {}",
            presig_id, owner_key
        )));
    }

    let presig: RedisValue = ctx.call(
        "HGET",
        &[&ctx.create_string(presig_key.clone()), &presig_id_str],
    )?;
    if let RedisValue::Null = presig {
        return Err(RedisError::String(format!(
            "WARN presignature {} is missing",
            presig_id
        )));
    }

    ctx.call("SREM", &[&ctx.create_string(owner_key), &presig_id_str])?;
    ctx.call("HDEL", &[&ctx.create_string(presig_key), &presig_id_str])?;
    ctx.call(
        "HSET",
        &[
            &ctx.create_string(used_key.clone()),
            &presig_id_str,
            &ctx.create_string("1"),
        ],
    )?;
    ctx.call(
        "HEXPIRE",
        &[
            &ctx.create_string(used_key),
            &ctx.create_string("86400"),
            &ctx.create_string("FIELDS"),
            &ctx.create_string("1"),
            &presig_id_str,
        ],
    )?;

    Ok(presig)
}

extern "C" fn presig_clear(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_clear' command".to_string(),
        ));
    }

    let account_id: AccountId = args[1]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;

    let owner_keys = get_owner_keys_presig(&account_id);
    let presig_key = get_presig_key(&account_id);
    let used_key = get_used_presig_key(&account_id);
    let reserved_key = get_reserved_presig_key(&account_id);

    let owner_keys_list: RedisValue =
        ctx.call("SMEMBERS", &[&ctx.create_string(owner_keys.clone())])?;
    let mut del_keys = vec![
        ctx.create_string(owner_keys),
        ctx.create_string(presig_key),
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

extern "C" fn presig_remove_outdated(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() < 2 {
        return Err(RedisError::String(
            "ERR wrong number of arguments for 'presig_remove_outdated' command".to_string(),
        ));
    }

    let account_id: AccountId = args[0]
        .to_string()
        .parse()
        .map_err(|_| RedisError::String("ERR invalid account_id".to_string()))?;
    let owner: Participant = Participant::from(
        args[1]
            .to_string()
            .parse::<u32>()
            .map_err(|_| RedisError::String("ERR invalid owner".to_string()))?,
    );
    let owner_shares: Vec<String> = args[2..].iter().map(|s| s.to_string()).collect();

    let presig_key = get_presig_key(&account_id);
    let reserved_key = get_reserved_presig_key(&account_id);
    let owner_keys = get_owner_keys_presig(&account_id);
    let owner_key = get_owner_key_presig(&owner_keys, owner);

    let our_shares: RedisValue = ctx.call("SMEMBERS", &[&ctx.create_string(owner_key.clone())])?;
    let mut outdated = Vec::new();

    if let RedisValue::Array(arr) = our_shares {
        for share in arr {
            if let RedisValue::SimpleString(id) = share {
                if !owner_shares.contains(&id) {
                    outdated.push(id);
                }
            }
        }
    }

    if !outdated.is_empty() {
        let mut srem_args = vec![
            ctx.create_string(owner_key),
            ctx.create_string(reserved_key),
        ];
        for id in &outdated {
            srem_args.push(ctx.create_string(id.clone()));
        }
        let srem_refs: Vec<&RedisString> = srem_args.iter().collect();
        ctx.call("SREM", &*srem_refs)?;

        let mut hdel_args = vec![ctx.create_string(presig_key)];
        for id in &outdated {
            hdel_args.push(ctx.create_string(id.clone()));
        }
        let hdel_refs: Vec<&RedisString> = hdel_args.iter().collect();
        ctx.call("HDEL", &*hdel_refs)?;
    }

    Ok(outdated.into())
}

redis_module::redis_module! {
    name: "mpc_redis_module",
    version: 1,
    allocator: (redis_module::alloc::RedisAlloc, redis_module::alloc::RedisAlloc),
    data_types: [],
    commands: [
        ["TEST", test_command, "write", 0, 0, 0],
        ["TRIPLES.RESERVE", triples_reserve, "write", 0, 0, 0],
        ["TRIPLES.INSERT", triples_insert, "write", 0, 0, 0],
        ["TRIPLES.TAKE_TWO", triples_take_two, "write", 0, 0, 0],
        ["TRIPLES.TAKE_TWO_MINE", triples_take_two_mine, "write", 0, 0, 0],
        ["TRIPLES.UNRESERVE", triples_unreserve, "write", 0, 0, 0],
        ["TRIPLES.REMOVE_OUTDATED", triples_remove_outdated, "write", 0, 0, 0],
        ["TRIPLES.CLEAR", triples_clear, "write", 0, 0, 0],
        ["PRESIG.RESERVE", presig_reserve, "write", 0, 0, 0],
        ["PRESIG.INSERT", presig_insert, "write", 0, 0, 0],
        ["PRESIG.TAKE", presig_take, "write", 0, 0, 0],
        ["PRESIG.TAKE_MINE", presig_take_mine, "write", 0, 0, 0],
        ["PRESIG.UNRESERVE", presig_unreserve, "write", 0, 0, 0],
        ["PRESIG.REMOVE_OUTDATED", presig_remove_outdated, "write", 0, 0, 0],
        ["PRESIG.CLEAR", presig_clear, "write", 0, 0, 0],
    ],
}

#[cfg(test)]
mod tests {
    // Tests removed due to redis_module testing not available
}
