use redis_module::{Context, RedisError, RedisResult, RedisString, RedisValue};

/// Command: mpc.checkpoint.persist
/// Arguments: checkpoint_key checkpoint_json
/// Returns: OK
pub fn checkpoint_persist(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 3 {
        return Err(RedisError::WrongArity);
    }

    let checkpoint_key = args[1].to_string_lossy();
    let checkpoint_json = args[2].to_string_lossy();

    // SET checkpoint_key checkpoint_json
    ctx.call("SET", &[&checkpoint_key, &checkpoint_json])?;

    Ok(RedisValue::SimpleString("OK".to_string()))
}

/// Command: mpc.checkpoint.load
/// Arguments: checkpoint_key
/// Returns: Bulk string or nil
pub fn checkpoint_load(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    if args.len() != 2 {
        return Err(RedisError::WrongArity);
    }

    let checkpoint_key = args[1].to_string_lossy();

    // GET checkpoint_key
    let result = ctx.call("GET", &[&checkpoint_key])?;

    Ok(result)
}
