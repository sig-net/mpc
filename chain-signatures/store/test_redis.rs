use redis_module::{Context, RedisResult, RedisString};

pub fn test_cmd(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    let res = ctx.call("SET", &["foo", "bar"])?;
    Ok(res)
}
