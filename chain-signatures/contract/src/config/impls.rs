use super::ProtocolConfig;
use near_sdk::serde::ser::SerializeStruct;
use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};

impl ProtocolConfig {
    pub fn new(
        min_mine_triple_pairs: u32,
        min_mine_presignatures: u32,
        max_mine_generations: u32,
    ) -> Self {
        Self {
            min_mine_triple_pairs,
            min_mine_presignatures,
            max_mine_generations,
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::new(512, 512, 16)
    }
}

impl Serialize for ProtocolConfig {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("ProtocolConfig", 4)?;
        s.serialize_field("min_mine_triple_pairs", &self.min_mine_triple_pairs)?;
        s.serialize_field("min_mine_presignatures", &self.min_mine_presignatures)?;
        s.serialize_field("max_mine_generations", &self.max_mine_generations)?;
        let deprecated = super::deprecated::ProtocolConfig::from_floors(
            self.min_mine_triple_pairs,
            self.min_mine_presignatures,
            self.max_mine_generations,
        );
        s.serialize_field("protocol", &deprecated)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ProtocolConfig {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ProtocolConfigHelper {
            #[serde(default)]
            min_mine_triple_pairs: Option<u32>,
            #[serde(default)]
            min_mine_presignatures: Option<u32>,
            #[serde(default)]
            max_mine_generations: Option<u32>,
            #[serde(default)]
            protocol: Option<super::deprecated::ProtocolConfig>,
        }

        let helper = ProtocolConfigHelper::deserialize(deserializer)?;
        let default = ProtocolConfig::default();
        let protocol = helper.protocol;

        let min_mine_triple_pairs = helper
            .min_mine_triple_pairs
            .or_else(|| protocol.as_ref().map(|p| p.triple.min_triples))
            .unwrap_or(default.min_mine_triple_pairs);

        let min_mine_presignatures = helper
            .min_mine_presignatures
            .or_else(|| protocol.as_ref().map(|p| p.presignature.min_presignatures))
            .unwrap_or(default.min_mine_presignatures);

        let max_mine_generations = helper
            .max_mine_generations
            .or_else(|| protocol.as_ref().map(|p| p.max_concurrent_introduction))
            .unwrap_or(default.max_mine_generations);

        Ok(ProtocolConfig::new(
            min_mine_triple_pairs,
            min_mine_presignatures,
            max_mine_generations,
        ))
    }
}
