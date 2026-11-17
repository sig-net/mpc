#![allow(deprecated)]

use near_sdk::serde::ser::SerializeStruct;
use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_EXPECTED_PARTICIPANTS: u32 = 32;
const NETWORK_MULTIPLIER: u32 = 128;

#[deprecated(
    since = "1.23.0",
    note = "Kept for backward compatibility with pre-1.23 nodes; use config::ProtocolConfig instead"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub message_timeout: u64,
    pub garbage_timeout: u64,
    pub max_concurrent_introduction: u32,
    pub max_concurrent_generation: u32,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
}

#[deprecated(
    since = "1.23.0",
    note = "Kept for backward compatibility with pre-1.23 nodes"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripleConfig {
    pub min_triples: u32,
    pub max_triples: u32,
    pub generation_timeout: u64,
}

#[deprecated(
    since = "1.23.0",
    note = "Kept for backward compatibility with pre-1.23 nodes"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresignatureConfig {
    pub min_presignatures: u32,
    pub max_presignatures: u32,
    pub generation_timeout: u64,
}

#[deprecated(
    since = "1.23.0",
    note = "Kept for backward compatibility with pre-1.23 nodes"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureConfig {
    pub generation_timeout: u64,
    pub generation_timeout_total: u64,
    pub garbage_timeout: u64,
}

#[allow(deprecated)]
impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::from_floors(512, 512, 16)
    }
}

#[allow(deprecated)]
impl ProtocolConfig {
    pub fn from_floors(triple_pairs: u32, presignatures: u32, generations: u32) -> Self {
        Self {
            message_timeout: 5 * 60 * 1000,
            garbage_timeout: 2 * 60 * 60 * 1000,
            max_concurrent_introduction: generations,
            max_concurrent_generation: generations * MAX_EXPECTED_PARTICIPANTS,
            triple: TripleConfig {
                min_triples: triple_pairs,
                max_triples: triple_pairs * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
                generation_timeout: 10 * 60 * 1000,
            },
            presignature: PresignatureConfig {
                min_presignatures: presignatures,
                max_presignatures: presignatures * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
                generation_timeout: 45 * 1000,
            },
            signature: SignatureConfig {
                generation_timeout: 45 * 1000,
                generation_timeout_total: 200 * 1000,
                garbage_timeout: 24 * 60 * 60 * 1000,
            },
        }
    }
}

#[allow(deprecated)]
impl Serialize for ProtocolConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("DeprecatedProtocolConfig", 7)?;
        s.serialize_field("message_timeout", &self.message_timeout)?;
        s.serialize_field("garbage_timeout", &self.garbage_timeout)?;
        s.serialize_field(
            "max_concurrent_introduction",
            &self.max_concurrent_introduction,
        )?;
        s.serialize_field("max_concurrent_generation", &self.max_concurrent_generation)?;
        s.serialize_field("triple", &self.triple)?;
        s.serialize_field("presignature", &self.presignature)?;
        s.serialize_field("signature", &self.signature)?;
        s.end()
    }
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for ProtocolConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_message_timeout")]
            message_timeout: u64,
            #[serde(default = "default_garbage_timeout")]
            garbage_timeout: u64,
            #[serde(default = "default_max_concurrent_introduction")]
            max_concurrent_introduction: u32,
            #[serde(default = "default_max_concurrent_generation")]
            max_concurrent_generation: u32,
            #[serde(default)]
            triple: Option<TripleConfig>,
            #[serde(default)]
            presignature: Option<PresignatureConfig>,
            #[serde(default)]
            signature: Option<SignatureConfig>,
        }
        fn default_message_timeout() -> u64 {
            5 * 60 * 1000
        }
        fn default_garbage_timeout() -> u64 {
            2 * 60 * 60 * 1000
        }
        fn default_max_concurrent_introduction() -> u32 {
            16
        }
        fn default_max_concurrent_generation() -> u32 {
            16 * MAX_EXPECTED_PARTICIPANTS
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            message_timeout: raw.message_timeout,
            garbage_timeout: raw.garbage_timeout,
            max_concurrent_introduction: raw.max_concurrent_introduction,
            max_concurrent_generation: raw.max_concurrent_generation,
            triple: raw.triple.unwrap_or(TripleConfig {
                min_triples: 512,
                max_triples: 512 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
                generation_timeout: 10 * 60 * 1000,
            }),
            presignature: raw.presignature.unwrap_or(PresignatureConfig {
                min_presignatures: 512,
                max_presignatures: 512 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
                generation_timeout: 45 * 1000,
            }),
            signature: raw.signature.unwrap_or(SignatureConfig {
                generation_timeout: 45 * 1000,
                generation_timeout_total: 200 * 1000,
                garbage_timeout: 24 * 60 * 60 * 1000,
            }),
        })
    }
}

#[allow(deprecated)]
impl Serialize for TripleConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("DeprecatedTripleConfig", 3)?;
        s.serialize_field("min_triples", &self.min_triples)?;
        s.serialize_field("max_triples", &self.max_triples)?;
        s.serialize_field("generation_timeout", &self.generation_timeout)?;
        s.end()
    }
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for TripleConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_min_triples")]
            min_triples: u32,
            #[serde(default = "default_max_triples")]
            max_triples: u32,
            #[serde(default = "default_generation_timeout")]
            generation_timeout: u64,
        }
        fn default_min_triples() -> u32 {
            512
        }
        fn default_max_triples() -> u32 {
            512 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER
        }
        fn default_generation_timeout() -> u64 {
            10 * 60 * 1000
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            min_triples: raw.min_triples,
            max_triples: raw.max_triples,
            generation_timeout: raw.generation_timeout,
        })
    }
}

#[allow(deprecated)]
impl Serialize for PresignatureConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("DeprecatedPresignatureConfig", 3)?;
        s.serialize_field("min_presignatures", &self.min_presignatures)?;
        s.serialize_field("max_presignatures", &self.max_presignatures)?;
        s.serialize_field("generation_timeout", &self.generation_timeout)?;
        s.end()
    }
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for PresignatureConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_min_presignatures")]
            min_presignatures: u32,
            #[serde(default = "default_max_presignatures")]
            max_presignatures: u32,
            #[serde(default = "default_generation_timeout")]
            generation_timeout: u64,
        }
        fn default_min_presignatures() -> u32 {
            512
        }
        fn default_max_presignatures() -> u32 {
            512 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER
        }
        fn default_generation_timeout() -> u64 {
            45 * 1000
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            min_presignatures: raw.min_presignatures,
            max_presignatures: raw.max_presignatures,
            generation_timeout: raw.generation_timeout,
        })
    }
}

#[allow(deprecated)]
impl Serialize for SignatureConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("DeprecatedSignatureConfig", 3)?;
        s.serialize_field("generation_timeout", &self.generation_timeout)?;
        s.serialize_field("generation_timeout_total", &self.generation_timeout_total)?;
        s.serialize_field("garbage_timeout", &self.garbage_timeout)?;
        s.end()
    }
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for SignatureConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_generation_timeout")]
            generation_timeout: u64,
            #[serde(default = "default_generation_timeout_total")]
            generation_timeout_total: u64,
            #[serde(default = "default_garbage_timeout")]
            garbage_timeout: u64,
        }
        fn default_generation_timeout() -> u64 {
            45 * 1000
        }
        fn default_generation_timeout_total() -> u64 {
            200 * 1000
        }
        fn default_garbage_timeout() -> u64 {
            24 * 60 * 60 * 1000
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            generation_timeout: raw.generation_timeout,
            generation_timeout_total: raw.generation_timeout_total,
            garbage_timeout: raw.garbage_timeout,
        })
    }
}
