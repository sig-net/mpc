use std::ops::Deref;

pub struct Redacted<T>(T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Redacted").field(&"[REDACTED]").finish()
    }
}

impl<T: Clone> Clone for Redacted<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn debug_redacts_inner_value() {
        let rendered = format!("{:?}", Redacted::new("redacted-sentinel".to_owned()));
        assert!(!rendered.contains("redacted-sentinel"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
