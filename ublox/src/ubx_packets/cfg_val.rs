use super::CfgInfMask;

pub struct KeyId(u32);

pub enum StorageSize {
    OneBit,
    OneByte,
    TwoBytes,
    FourBytes,
    EightBytes,
}

impl StorageSize {
    pub const fn to_usize(self) -> usize {
        match self {
            Self::OneBit | Self::OneByte => 1,
            Self::TwoBytes => 2,
            Self::FourBytes => 4,
            Self::EightBytes => 8,
        }
    }
}

impl KeyId {
    pub(crate) const SIZE: usize = 4;

    pub const fn value_size(&self) -> StorageSize {
        match (self.0 >> 28) & 0b111 {
            1 => StorageSize::OneBit,
            2 => StorageSize::OneByte,
            3 => StorageSize::TwoBytes,
            4 => StorageSize::FourBytes,
            5 => StorageSize::EightBytes,

            // TODO: Replace this with unreachable!() when we upgrade to MSRV 1.57
            // Since it's unreachable we get to pick an arbitrary value
            //_ => unreachable!(),
            _ => StorageSize::OneBit,
        }
    }

    pub const fn group_id(&self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn item_id(&self) -> u8 {
        self.0 as u8
    }

    pub fn extend_to<T>(&self, buf: &mut T) -> usize
    where
        T: core::iter::Extend<u8>,
    {
        let bytes = self.0.to_le_bytes();
        let byte_len: usize = bytes.len();
        for b in bytes.iter() {
            buf.extend(core::iter::once(*b));
        }

        byte_len
    }
}

macro_rules! from_cfg_v_bytes {
    ($buf:expr, bool) => {
        match $buf[0] {
            0 => false,
            1 => true,
            _ => unreachable!(),
        }
    };
    ($buf:expr, u8) => {
        $buf[0]
    };
    ($buf:expr, i8) => {
        i8::from_le_bytes([$buf[0]])
    };
    ($buf:expr, u16) => {
        u16::from_le_bytes([$buf[0], $buf[1]])
    };
    ($buf:expr, i16) => {
        i16::from_le_bytes([$buf[0], $buf[1]])
    };
    ($buf:expr, u32) => {
        u32::from_le_bytes([$buf[0], $buf[1], $buf[2], $buf[3]])
    };
    ($buf:expr, i32) => {
        i32::from_le_bytes([$buf[0], $buf[1], $buf[2], $buf[3]])
    };
    ($buf:expr, u64) => {
        u64::from_le_bytes([
            $buf[0], $buf[1], $buf[2], $buf[3], $buf[4], $buf[5], $buf[6], $buf[7],
        ])
    };
    ($buf:expr, f32) => {
        f32::from_le_bytes([$buf[0], $buf[1], $buf[2], $buf[3]])
    };
    ($buf:expr, f64) => {
        f64::from_le_bytes([
            $buf[0], $buf[1], $buf[2], $buf[3], $buf[4], $buf[5], $buf[6], $buf[7],
        ])
    };
    ($buf:expr, CfgInfMask) => {
        CfgInfMask::from_bits_truncate($buf[0])
    };
    ($buf:expr, EngineSelection) => {
        match $buf[0] {
            0 => EngineSelection::Ext,
            1 => EngineSelection::Madc,
            _ => unreachable!(),
        }
    };
    ($buf:expr, LnaMode) => {
        match $buf[0] {
            0 => LnaMode::Normal,
            1 => LnaMode::LowGain,
            2 => LnaMode::Bypass,
            _ => unreachable!(),
        }
    };
    ($buf:expr, AntennaSetting) => {
        match $buf[0] {
            0 => AntennaSetting::Unknown,
            1 => AntennaSetting::Passive,
            2 => AntennaSetting::Active,
            _ => unreachable!(),
        }
    };
    ($buf:expr, FixMode) => {
        match $buf[0] {
            0 => FixMode::TwoDOnly,
            1 => FixMode::ThreeDOnly,
            2 => FixMode::Auto,
            _ => unreachable!(),
        }
    };
    ($buf:expr, UtcStandard) => {
        match $buf[0] {
            0 => UtcStandard::Auto,
            3 => UtcStandard::USNO,
            5 => UtcStandard::EU,
            6 => UtcStandard::SU,
            7 => UtcStandard::NTSC,
            8 => UtcStandard::NPLI,
            9 => UtcStandard::NICT,
            _ => unreachable!(),
        }
    };
    ($buf:expr, DynamicModel) => {
        match $buf[0] {
            0 => DynamicModel::Portable,
            2 => DynamicModel::Stationary,
            3 => DynamicModel::Pedestrian,
            4 => DynamicModel::Automotive,
            5 => DynamicModel::Sea,
            6 => DynamicModel::Air1,
            7 => DynamicModel::Air2,
            8 => DynamicModel::Air4,
            9 => DynamicModel::Wrist,
            10 => DynamicModel::Bike,
            11 => DynamicModel::Mower,
            12 => DynamicModel::Escooter,
            _ => unreachable!(),
        }
    };
    ($buf:expr, ProtocolVersion) => {
        match $buf[0] {
            21 => ProtocolVersion::V21,
            23 => ProtocolVersion::V23,
            40 => ProtocolVersion::V40,
            41 => ProtocolVersion::V41,
            42 => ProtocolVersion::V411,
            _ => unreachable!(),
        }
    };
    ($buf:expr, MaxSvs) => {
        match $buf[0] {
            0 => MaxSvs::Unlim,
            8 => MaxSvs::Eight,
            12 => MaxSvs::Twelve,
            16 => MaxSvs::Sixteen,
            _ => unreachable!(),
        }
    };
    ($buf:expr, SatelliteNumbering) => {
        match $buf[0] {
            0 => SatelliteNumbering::Strict,
            1 => SatelliteNumbering::Extended,
            _ => unreachable!(),
        }
    };
    ($buf:expr, MainTalkerId) => {
        match $buf[0] {
            0 => MainTalkerId::Auto,
            1 => MainTalkerId::Gp,
            2 => MainTalkerId::Gl,
            3 => MainTalkerId::Gn,
            4 => MainTalkerId::Ga,
            5 => MainTalkerId::Gb,
            7 => MainTalkerId::Gq,
            _ => unreachable!(),
        }
    };
    ($buf:expr, GsvTalkerId) => {
        match $buf[0] {
            0 => GsvTalkerId::Gnss,
            1 => GsvTalkerId::Main,
            _ => unreachable!(),
        }
    };
    ($buf:expr, OdometerProfile) => {
        match $buf[0] {
            0 => OdometerProfile::Running,
            1 => OdometerProfile::Cycling,
            2 => OdometerProfile::Swimming,
            3 => OdometerProfile::Car,
            4 => OdometerProfile::Custom,
            _ => unreachable!(),
        }
    };
    ($buf:expr, PmOperationMode) => {
        match $buf[0] {
            0 => PmOperationMode::Full,
            1 => PmOperationMode::PsmOO,
            2 => PmOperationMode::PmsCT,
            _ => unreachable!(),
        }
    };
    ($buf:expr, TimeReference) => {
        match $buf[0] {
            0 => TimeReference::Utc,
            1 => TimeReference::Gps,
            2 => TimeReference::Glo,
            3 => TimeReference::Bds,
            4 => TimeReference::Gal,
            5 => TimeReference::Navic,
            15 => TimeReference::Local,
            _ => unreachable!(),
        }
    };
    ($buf:expr, TXReadyInterface) => {
        match $buf[0] {
            0 => TXReadyInterface::I2c,
            1 => TXReadyInterface::Spi,
            _ => unreachable!(),
        }
    };
    ($buf:expr, DataBits) => {
        match $buf[0] {
            0 => DataBits::Eight,
            1 => DataBits::Seven,
            _ => unreachable!(),
        }
    };
    ($buf:expr, Parity) => {
        match $buf[0] {
            0 => Parity::None,
            1 => Parity::Odd,
            2 => Parity::Even,
            _ => unreachable!(),
        }
    };
    ($buf:expr, StopBits) => {
        match $buf[0] {
            0 => StopBits::Half,
            1 => StopBits::One,
            2 => StopBits::OneHalf,
            3 => StopBits::Two,
            _ => unreachable!(),
        }
    };
    ($buf:expr, AlignmentToReferenceTime) => {
        match $buf[0] {
            0 => AlignmentToReferenceTime::Utc,
            1 => AlignmentToReferenceTime::Gps,
            2 => AlignmentToReferenceTime::Glo,
            3 => AlignmentToReferenceTime::Bds,
            4 => AlignmentToReferenceTime::Gal,
            _ => unreachable!(),
        }
    };
    ($buf:expr, TpPulse) => {
        match $buf[0] {
            0 => TpPulse::Period,
            1 => TpPulse::Freq,
            _ => unreachable!(),
        }
    };
    ($buf:expr, TpPulseLength) => {
        match $buf[0] {
            0 => TpPulseLength::Ratio,
            1 => TpPulseLength::Length,
            _ => unreachable!(),
        }
    };
}

macro_rules! into_cfg_kv_bytes {
    (@inner [$($byte:expr),+]) => {{
      let key_id = Self::KEY.0.to_le_bytes();

      [
        key_id[0], key_id[1], key_id[2], key_id[3],
        $(
          $byte,
        )*
      ]
    }};
    ($this:expr, bool) => {
      into_cfg_kv_bytes!(@inner [$this.0 as u8])
    };
    ($this:expr, u8) => {{
      into_cfg_kv_bytes!(@inner [$this.0])
    }};
    ($this:expr, i8) => {{
        let bytes = $this.0.to_le_bytes();
        into_cfg_kv_bytes!(@inner [bytes[0]])
    }};
    ($this:expr, u16) => {{
      let bytes = $this.0.to_le_bytes();
      into_cfg_kv_bytes!(@inner [bytes[0], bytes[1]])
    }};
    ($this:expr, i16) => {{
      let bytes = $this.0.to_le_bytes();
      into_cfg_kv_bytes!(@inner [bytes[0], bytes[1]])
    }};
    ($this:expr, u32) => {{
      let bytes = $this.0.to_le_bytes();
      into_cfg_kv_bytes!(@inner [bytes[0], bytes[1], bytes[2], bytes[3]])
    }};
    ($this:expr, i32) => {{
        let bytes = $this.0.to_le_bytes();
        into_cfg_kv_bytes!(@inner [bytes[0], bytes[1], bytes[2], bytes[3]])
      }};
    ($this:expr, u64) => {{
      let bytes = $this.0.to_le_bytes();
      into_cfg_kv_bytes!(@inner [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
    }};
    ($this:expr, f32) => {{
        let bytes = $this.0.to_le_bytes();
        into_cfg_kv_bytes!(@inner [bytes[0], bytes[1], bytes[2], bytes[3]])
    }};
    ($this:expr, f64) => {{
        let bytes = $this.0.to_le_bytes();
        into_cfg_kv_bytes!(@inner [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
    }};
    ($this:expr, CfgInfMask) => {
      into_cfg_kv_bytes!(@inner [
        $this.0.bits()
      ])
    };
    ($this:expr, EngineSelection) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                EngineSelection::Ext => 0,
                EngineSelection::Madc => 1,
            }
        ])
    };
    ($this:expr, LnaMode) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                LnaMode::Normal => 0,
                LnaMode::LowGain => 1,
                LnaMode::Bypass => 2,
            }
        ])
    };
    ($this:expr, AntennaSetting) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                AntennaSetting::Unknown => 0,
                AntennaSetting::Passive => 1,
                AntennaSetting::Active => 2,
            }
        ])
    };
    ($this:expr, FixMode) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                FixMode::TwoDOnly => 0,
                FixMode::ThreeDOnly => 1,
                FixMode::Auto => 2,
            }
        ])
    };
    ($this:expr, UtcStandard) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                UtcStandard::Auto => 0,
                UtcStandard::USNO => 3,
                UtcStandard::EU => 3,
                UtcStandard::SU => 3,
                UtcStandard::NTSC => 3,
                UtcStandard::NPLI => 3,
                UtcStandard::NICT => 3,
            }
        ])
    };
    ($this:expr, DynamicModel) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                DynamicModel::Portable => 0,
                DynamicModel::Stationary => 2,
                DynamicModel::Pedestrian => 3,
                DynamicModel::Automotive => 4,
                DynamicModel::Sea => 5,
                DynamicModel::Air1 => 6,
                DynamicModel::Air2 => 7,
                DynamicModel::Air4 => 8,
                DynamicModel::Wrist => 9,
                DynamicModel::Bike => 10,
                DynamicModel::Mower => 11,
                DynamicModel::Escooter => 12,
            }
        ])
    };
    ($this:expr, ProtocolVersion) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                ProtocolVersion::V21 => 21,
                ProtocolVersion::V23 => 23,
                ProtocolVersion::V40 => 40,
                ProtocolVersion::V41 => 42,
                ProtocolVersion::V411 => 42,
            }
        ])
    };
    ($this:expr, MaxSvs) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                MaxSvs::Unlim => 0,
                MaxSvs::Eight => 8,
                MaxSvs::Twelve => 12,
                MaxSvs::Sixteen => 16,
            }
        ])
    };
    ($this:expr, SatelliteNumbering) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                SatelliteNumbering::Strict => 0,
                SatelliteNumbering::Extended => 1,
            }
        ])
    };
    ($this:expr, MainTalkerId) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                MainTalkerId::Auto => 0,
                MainTalkerId::Gp => 1,
                MainTalkerId::Gl => 2,
                MainTalkerId::Gn => 3,
                MainTalkerId::Ga => 4,
                MainTalkerId::Gb => 5,
                MainTalkerId::Gq => 7,
            }
        ])
    };
    ($this:expr, GsvTalkerId) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                GsvTalkerId::Gnss => 0,
                GsvTalkerId::Main => 1,
            }
        ])
    };
    ($this:expr, OdometerProfile) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                OdometerProfile::Running => 0,
                OdometerProfile::Cycling => 1,
                OdometerProfile::Swimming => 2,
                OdometerProfile::Car => 3,
                OdometerProfile::Custom => 4,
            }
        ])
    };
    ($this:expr, PmOperationMode) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                PmOperationMode::Full => 0,
                PmOperationMode::PsmOO => 1,
                PmOperationMode::PmsCT => 2,
            }
        ])
    };
    ($this:expr, TimeReference) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                TimeReference::Utc => 0,
                TimeReference::Gps => 1,
                TimeReference::Glo => 2,
                TimeReference::Bds => 3,
                TimeReference::Gal => 4,
                TimeReference::Navic => 5,
                TimeReference::Local => 15,
            }
        ])
    };
    ($this:expr, TXReadyInterface) => {
        into_cfg_kv_bytes!(@inner [
            match $this.0 {
                TXReadyInterface::I2c => 0,
                TXReadyInterface::Spi => 1,
            }
        ])
    };
    ($this:expr, DataBits) => {
      into_cfg_kv_bytes!(@inner [
        match $this.0 {
          DataBits::Eight => 0,
          DataBits::Seven => 1,
        }
      ])
    };
    ($this:expr, Parity) => {
      into_cfg_kv_bytes!(@inner [
        match $this.0 {
          Parity::None => 0,
          Parity::Odd => 1,
          Parity::Even => 2,
        }
      ])
    };
    ($this:expr, StopBits) => {
      into_cfg_kv_bytes!(@inner [
        match $this.0 {
          StopBits::Half => 0,
          StopBits::One => 1,
          StopBits::OneHalf => 2,
          StopBits::Two => 3,
        }
      ])
    };
    ($this:expr, AlignmentToReferenceTime) => {
      into_cfg_kv_bytes!(@inner [
          $this.0 as u8
      ])
    };
    ($this:expr, TpPulse) => {
      into_cfg_kv_bytes!(@inner [
          $this.0 as u8
      ])
    };
    ($this:expr, TpPulseLength) => {
      into_cfg_kv_bytes!(@inner [
          $this.0 as u8
      ])
    };
}

macro_rules! cfg_val {
  (
    $(
      $(#[$class_comment:meta])*
      $cfg_item:ident, $cfg_key_id:expr, $cfg_value_type:ident,
    )*
  ) => {
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum CfgVal {
      $(
        $(#[$class_comment])*
        $cfg_item($cfg_value_type),
      )*
    }

    impl CfgVal {
      pub const fn len(&self) -> usize {
        match self {
          $(
            Self::$cfg_item(_) => {
              $cfg_item::SIZE
            }
          )*
        }
      }

      pub const fn is_empty(&self) -> bool {
          self.len() == 0
      }

      #[track_caller]
      pub fn parse(buf: &[u8]) -> Self {
        let key_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        match key_id {
          $(
            $cfg_key_id => {
              Self::$cfg_item(from_cfg_v_bytes!(&buf[4..], $cfg_value_type))
            },
          )*
          _ => unimplemented!("unknown key ID: 0x{:8X}", key_id),
        }
      }

      pub fn extend_to<T>(&self, buf: &mut T) -> usize
      where
          T: core::iter::Extend<u8>
      {
        match self {
          $(
            Self::$cfg_item(value) => {
              let bytes = $cfg_item(*value).into_cfg_kv_bytes();
              let bytes_len = bytes.len();
              // TODO: extend all the bytes in one extend() call when we bump MSRV
              for b in bytes.iter() {
                buf.extend(core::iter::once(*b));
              }
              bytes_len
            }
          )*
        }
      }

      pub fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
          $(
            Self::$cfg_item(value) => {
              let kv: [u8; $cfg_item::SIZE] = $cfg_item(*value).into_cfg_kv_bytes();
              buf[..kv.len()].copy_from_slice(&kv[..]);
              kv.len()
            }
          )*
        }
      }
    }

    $(
      pub struct $cfg_item(pub $cfg_value_type);

      impl $cfg_item {
        pub const KEY: KeyId = KeyId($cfg_key_id);
        const SIZE: usize = KeyId::SIZE + Self::KEY.value_size().to_usize();

        pub fn into_cfg_kv_bytes(self) -> [u8; Self::SIZE] {
          into_cfg_kv_bytes!(self, $cfg_value_type)
        }
      }
    )*
  }
}

cfg_val! {
  // // CFG-ANA
  AnaUseAna,            0x10230001, bool,
//   AnaOrbMaxErr, 0x30230002, u16,

  // CFG-BATCH
  BatchEnable,          0x10260013, bool,
  BatchPioEnable,       0x10260014, bool,
  BatchMaxEntries,      0x30260015, u16,
  BatchWarnThrs,        0x30260016, u16,
  BatchPioActiveLow,    0x10260018, bool,
  BatchPioId,           0x20260019, u8,
  BatchExtraPvt,        0x1026001a, bool,
  BatchExtraOdo,        0x1026001b, bool,

  // CFG-BDS
  BdsUseGeoPrn,         0x10340014, bool, // Use BeiDou geostationary satellites

  // CFG-HW
  HwAntCfgVoltCtrl,     0x10a3002e, bool, // Active antenna voltage control flag
  HwAntCfgShortDet,     0x10a3002f, bool, // Short antenna detection flag
  HwAntCfgShortDelPol,  0x10a30030, bool, // Short antenna detection polarity
  HwAntCfgOpenDet,      0x10a30031, bool, // Open antenna detection flag
  HwAntCfgOpenDetPol,   0x10a30032, bool, // Open antenna detection polarity
  HwAntCfgPwrDown,      0x10a30033, bool, // Power down antenna flga
  HwAntCFGPwrDownPol,   0x10a30034, bool, // Power down antenna logic polarity
  HwAntCfgRecover,      0x10a30035, bool, // Automatic recovery from short state flag
  HwAntSupSwitchPin,    0x20a30036, u8, // ANT1 PIO number
  HwAntSupShortPin,     0x20a30037, u8, // ANT0 PIO number
  HwAntSupOpenPin,      0x20a30038, u8, // ANT2 PIO number
  HwAntOnShortUs,       0x30a3003c, u16, // ANT on->short timeout[us]
  HwAntSupEngine,       0x20a30054, EngineSelection, // Antenna supervisor engine selection ** Needs enum definition
  HwAntSupShortThr,     0x20a30055, u8, // Antenna supervisor MADC engine short detection threshold
  HwAntSupOpenThr,      0x20a30056, u8, // Antenna supervisor MADC engine open detection threshold
  HwRfLnaMode,          0x20a30057, LnaMode, // Mode for internal LNA

  // CFG-I2C
  I2cAddress,           0x20510001, u8, // I2c address of the receiver (7 bits)
  I2cExtendedTimeout,   0x10510002, bool, // Flag to disable timeouting the interface after 1.5s
  I2cEnabled,           0x10510003, bool, // Flag to indicate if the I2c interface should be enabled

  // CFG-I2CINPROT
  I2cInProtUBX,         0x10710001, bool, // Flag to indicate if UBX should ber an input protocol on I2c
  I2cInProtNMEA,        0x10710002, bool, // Flag to indicate if NMEA should ber an input protocol on I2c

  // CFG-I2COUTPROT
  I2cOutProtUBX,         0x10720001, bool, // Flag to indicate if UBX should ber an input protocol on I2c
  I2cOutProtNMEA,        0x10720002, bool, // Flag to indicate if NMEA should ber an input protocol on I2c

  // CFG-INFMSG
  InfmsgUbxI2c,          0x20920001, CfgInfMask, // Information message enable flags for the UBX protocol on the I2c interface
  InfmsgUbxUart1,        0x20920002, CfgInfMask, // Information message enable flags for the UBX protocol on the UART1 interface
  InfmsgUbxSpi,          0x20920005, CfgInfMask, // Information message enable flags for the UBX protocol on the SPI interface
  InfmsgNmeaI2c,         0x20920006, CfgInfMask, // Information message enable flags for the NMEA protocol on the I2c interface
  InfmsgNmeaUart1,       0x20920007, CfgInfMask, // Information message enable flags for the NMEA protocol on the UART1 interface
  InfmsgNmeaSpi,         0x2092000a, CfgInfMask, // Information message enable flags for the NMEA protocol on the SPI interface

  // CFG-ITFM
  ItfmBBThreshold,       0x20410001, u8, // Broadband jamming detection threshold
  ItfmCWThreshold,       0x20410002, u8, // CW jamming detection threshold
  ItfmEnable,            0x1041000d, bool, // Enable interference detection
  ItfmAntSetting,        0x20410010, AntennaSetting, // Antenna setting
  ItfmEnableAux,         0x10410013, bool, // Scan auxillary bands

  // CFG-MOT
  MotGnssSpeedThrs,     0x20250038, u8, // GNSS speed threshold below which platform is considered as stationary
  MotGnssDistThrs,      0x3025003b, u16, // Distance above which GNSS-based stationary motion is exit

    // CFG-MSGOUT
  /// Output rate of the NMEA-GX-DTM message on port I2C
  MsgoutNmeaIdDtmI2c, 0x209100a6, u8,
  /// Output rate of the NMEA-GX-DTM message on port SPI
  MsgoutNmeaIdDtmSpi, 0x209100aa, u8,
  /// Output rate of the NMEA-GX-DTM message on port UART1
  MsgoutNmeaIdDtmUart1, 0x209100a7, u8,
  /// Output rate of the NMEA-GX-GBS message on port I2C
  MsgoutNmeaIdGbsI2c, 0x209100dd, u8,
  /// Output rate of the NMEA-GX-GBS message on port SPI
  MsgoutNmeaIdGbsSpi, 0x209100e1, u8,
  /// Output rate of the NMEA-GX-GBS message on port UART1
  MsgoutNmeaIdGbsUart1, 0x209100de, u8,
  /// Output rate of the NMEA-GX-GGA message on port I2C
  MsgoutNmeaIdGgaI2c, 0x209100ba, u8,
  /// Output rate of the NMEA-GX-GGA message on port SPI
  MsgoutNmeaIdGgaSpi, 0x209100be, u8,
  /// Output rate of the NMEA-GX-GGA message on port UART1
  MsgoutNmeaIdGgaUart1, 0x209100bb, u8,
  /// Output rate of the NMEA-GX-GLL message on port I2C
  MsgoutNmeaIdGllI2c, 0x209100c9, u8,
  /// Output rate of the NMEA-GX-GLL message on port SPI
  MsgoutNmeaIdGllSpi, 0x209100cd, u8,
  /// Output rate of the NMEA-GX-GLL message on port UART1
  MsgoutNmeaIdGllUart1, 0x209100ca, u8,
  /// Output rate of the NMEA-GX-GNS message on port I2C
  MsgoutNmeaIdGnsI2c, 0x209100b5, u8,
  /// Output rate of the NMEA-GX-GNS message on port SPI
  MsgoutNmeaIdGnsSpi, 0x209100b9, u8,
  /// Output rate of the NMEA-GX-GNS message on port UART1
  MsgoutNmeaIdGnsUart1, 0x209100b6, u8,
  /// Output rate of the NMEA-GX-GRS message on port I2C
  MsgoutNmeaIdGrsI2c, 0x209100ce, u8,
  /// Output rate of the NMEA-GX-GRS message on port SPI
  MsgoutNmeaIdGrsSpi, 0x209100d2, u8,
  /// Output rate of the NMEA-GX-GRS message on port UART1
  MsgoutNmeaIdGrsUart1, 0x209100cf, u8,
  /// Output rate of the NMEA-GX-GSA message on port I2C
  MsgoutNmeaIdGsaI2c, 0x209100bf, u8,
  /// Output rate of the NMEA-GX-GSA message on port SPI
  MsgoutNmeaIdGsaSpi, 0x209100c3, u8,
  /// Output rate of the NMEA-GX-GSA message on port UART1
  MsgoutNmeaIdGsaUart1, 0x209100c0, u8,
  /// Output rate of the NMEA-GX-GST message on port I2C
  MsgoutNmeaIdGstI2c, 0x209100d3, u8,
  /// Output rate of the NMEA-GX-GST message on port SPI
  MsgoutNmeaIdGstSpi, 0x209100d7, u8,
  /// Output rate of the NMEA-GX-GST message on port UART1
  MsgoutNmeaIdGstUart1, 0x209100d4, u8,
  /// Output rate of the NMEA-GX-GSV message on port I2C
  MsgoutNmeaIdGsvI2c, 0x209100c4, u8,
  /// Output rate of the NMEA-GX-GSV message on port SPI
  MsgoutNmeaIdGsvSpi, 0x209100c8, u8,
  /// Output rate of the NMEA-GX-GSV message on port UART1
  MsgoutNmeaIdGsvUart1, 0x209100c5, u8,
  /// Output rate of the NMEA-GX-RLM message on port I2C
  MsgoutNmeaIdRlmI2c, 0x20910400, u8,
  /// Output rate of the NMEA-GX-RLM message on port SPI
  MsgoutNmeaIdRlmSpi, 0x20910404, u8,
  /// Output rate of the NMEA-GX-RLM message on port UART1
  MsgoutNmeaIdRlmUart1, 0x20910401, u8,
  /// Output rate of the NMEA-GX-RMC message on port I2C
  MsgoutNmeaIdRmcI2c, 0x209100ab, u8,
  /// Output rate of the NMEA-GX-RMC message on port SPI
  MsgoutNmeaIdRmcSpi, 0x209100af, u8,
  /// Output rate of the NMEA-GX-RMC message on port UART1
  MsgoutNmeaIdRmcUart1, 0x209100ac, u8,
  /// Output rate of the NMEA-GX-VLW message on port I2C
  MsgoutNmeaIdVlwI2c, 0x209100e7, u8,
  /// Output rate of the NMEA-GX-VLW message on port SPI
  MsgoutNmeaIdVlwSpi, 0x209100eb, u8,
  /// Output rate of the NMEA-GX-VLW message on port UART1
  MsgoutNmeaIdVlwUart1, 0x209100e8, u8,
  /// Output rate of the NMEA-GX-VTG message on port I2C
  MsgoutNmeaIdVtgI2c, 0x209100b0, u8,
  /// Output rate of the NMEA-GX-VTG message on port SPI
  MsgoutNmeaIdVtgSpi, 0x209100b4, u8,
  /// Output rate of the NMEA-GX-VTG message on port UART1
  MsgoutNmeaIdVtgUart1, 0x209100b1, u8,
  /// Output rate of the NMEA-GX-ZDA message on port I2C
  MsgoutNmeaIdZdaI2c, 0x209100d8, u8,
  /// Output rate of the NMEA-GX-ZDA message on port SPI
  MsgoutNmeaIdZdaSpi, 0x209100dc, u8,
  /// Output rate of the NMEA-GX-ZDA message on port UART1
  MsgoutNmeaIdZdaUart1, 0x209100d9, u8,
  /// Output rate of the NMEA-GX-PUBX00 message on port I2C
  MsgoutPubxIdPolypI2c, 0x209100ec, u8,
  /// Output rate of the NMEA-GX-PUBX00 message on port SPI
  MsgoutPubxIdPolypSpi, 0x209100f0, u8,
  /// Output rate of the NMEA-GX-PUBX00 message on port UART1
  MsgoutPubxIdPolypUart1, 0x209100ed, u8,
  /// Output rate of the NMEA-GX-PUBX03 message on port I2C
  MsgoutPubxIdPolysI2c, 0x209100f1, u8,
  /// Output rate of the NMEA-GX-PUBX03 message on port SPI
  MsgoutPubxIdPolysSpi, 0x209100f5, u8,
  /// Output rate of the NMEA-GX-PUBX03 message on port UART1
  MsgoutPubxIdPolysUart1, 0x209100f2, u8,
  /// Output rate of the NMEA-GX-PUBX04 message on port I2C
  MsgoutPubxIdPolytI2c, 0x209100f6, u8,
  /// Output rate of the NMEA-GX-PUBX04 message on port SPI
  MsgoutPubxIdPolytSpi, 0x209100fa, u8,
  /// Output rate of the NMEA-GX-PUBX04 message on port UART1
  MsgoutPubxIdPolytUart1, 0x209100f7, u8,
  /// Output rate of the UBX-MONCOMMS message on port I2C
  MsgoutUbxMonCommsI2c, 0x2091034f, u8,
  /// Output rate of the UBX-MONCOMMS message on port SPI
  MsgoutUbxMonCommsSpi, 0x20910353, u8,
  /// Output rate of the UBX-MONCOMMS message on port UART1
  MsgoutUbxMonCommsUart1, 0x20910350, u8,
  /// Output rate of the UBX-MON-HW2 message on port I2C
  MsgoutUbxMonHw2I2c, 0x209101b9, u8,
  /// Output rate of the UBX-MON-HW2 message on port SPI
  MsgoutUbxMonHw2Spi, 0x209101bd, u8,
  /// Output rate of the UBX-MON-HW2 message on port UART1
  MsgoutUbxMonHw2Uart1, 0x209101ba, u8,
  /// Output rate of the UBX-MON-HW3 message on port I2C
  MsgoutUbxMonHw3I2c, 0x20910354, u8,
  /// Output rate of the UBX-MON-HW3 message on port SPI
  MsgoutUbxMonHw3Spi, 0x20910358, u8,
  /// Output rate of the UBX-MON-HW3 message on port UART1
  MsgoutUbxMonHw3Uart1, 0x20910355, u8,
  /// Output rate of the UBX-MON-HW message on port I2C
  MsgoutUbxMonHwI2c, 0x209101b4, u8,
  /// Output rate of the UBX-MON-HW message on port SPI
  MsgoutUbxMonHwSpi, 0x209101b8, u8,
  /// Output rate of the UBX-MON-HW message on port UART1
  MsgoutUbxMonHwUart1, 0x209101b5, u8,
  /// Output rate of the UBX-MON-IO message on port I2C
  MsgoutUbxMonIoI2c, 0x209101a5, u8,
  /// Output rate of the UBX-MON-IO message on port SPI
  MsgoutUbxMonIoSpi, 0x209101a9, u8,
  /// Output rate of the UBX-MON-IO message on port UART1
  MsgoutUbxMonIoUart1, 0x209101a6, u8,
  /// Output rate of the UBX-MON-MSGPP message on port I2C
  MsgoutUbxMonMsgPpI2c, 0x20910196, u8,
  /// Output rate of the UBX-MON-MSGPP message on port SPI
  MsgoutUbxMonMsgPpSpi, 0x2091019a, u8,
  /// Output rate of the UBX-MON-MSGPP message on port UART1
  MsgoutUbxMonMsgPpUart1, 0x20910197, u8,
  /// Output rate of the UBX-MON-RF message on port I2C
  MsgoutUbxMonRfI2c, 0x20910359, u8,
  /// Output rate of the UBX-MON-RF message on port SPI
  MsgoutUbxMonRfSpi, 0x2091035d, u8,
  /// Output rate of the UBX-MON-RF message on port UART1
  MsgoutUbxMonRfUart1, 0x2091035a, u8,
  /// Output rate of the UBX-MON-RXBUF message on port I2C
  MsgoutUbxMonRxbufI2c, 0x209101a0, u8,
  /// Output rate of the UBX-MON-RXBUF message on port SPI
  MsgoutUbxMonRxbufSpi, 0x209101a4, u8,
  /// Output rate of the UBX-MON-RXBUF message on port UART1
  MsgoutUbxMonRxbufUart1, 0x209101a1, u8,
  /// Output rate of the UBX-MON-RXR message on port I2C
  MsgoutUbxMonRxrI2c, 0x20910187, u8,
  /// Output rate of the UBX-MON-RXR message on port SPI
  MsgoutUbxMonRxrSpi, 0x2091018b, u8,
  /// Output rate of the UBX-MON-RXR message on port UART1
  MsgoutUbxMonRxrUart1, 0x20910188, u8,
  /// Output rate of the UBX-MON-SPAN message on port I2C
  MsgoutUbxMonSpanI2c, 0x2091038b, u8,
  /// Output rate of the UBX-MON-SPAN message on port SPI
  MsgoutUbxMonSpanSpi, 0x2091038f, u8,
  /// Output rate of the UBX-MON-SPAN message on port UART1
  MsgoutUbxMonSpanUart1, 0x2091038c, u8,
  /// Output rate of the UBX-MON-TXBUF message on port I2C
  MsgoutUbxMonTxbufI2c, 0x2091019b, u8,
  /// Output rate of the UBX-MON-TXBUF message on port SPI
  MsgoutUbxMonTxbufSpi, 0x2091019f, u8,
  /// Output rate of the UBX-MON-TXBUF message on port UART1
  MsgoutUbxMonTxbufUart1, 0x2091019c, u8,
  /// Output rate of the UBX-NAV-AOPSTATUS message on port I2C
  MsgoutUbxNavAopStatusI2c, 0x20910079, u8,
  /// Output rate of the UBX-NAV-AOPSTATUS message on port SPI
  MsgoutUbxNavAopStatusSpi, 0x2091007d, u8,
  /// Output rate of the UBX-NAV-AOPSTATUS message on port UART1
  MsgoutUbxNavAopStatusUart1, 0x2091007a, u8,
  /// Output rate of the UBX-NAV-CLOCK message on port I2C
  MsgoutUbxNavClockI2c, 0x20910065, u8,
  /// Output rate of the UBX-NAV-CLOCK message on port SPI
  MsgoutUbxNavClockSpi, 0x20910069, u8,
  /// Output rate of the UBX-NAV-CLOCK message on port UART1
  MsgoutUbxNavClockUart1, 0x20910066, u8,
  /// Output rate of the UBX-NAV-COV message on port I2C
  MsgoutUbxNavCovI2c, 0x20910083, u8,
  /// Output rate of the UBX-NAV-COV message on port SPI
  MsgoutUbxNavCovSpi, 0x20910087, u8,
  /// Output rate of the UBX-NAV-COV message on port UART1
  MsgoutUbxNavCovUart1, 0x20910084, u8,
  /// Output rate of the UBX-NAV-DOP message on port I2C
  MsgoutUbxNavDopI2c, 0x20910038, u8,
  /// Output rate of the UBX-NAV-DOP message on port SPI
  MsgoutUbxNavDopSpi, 0x2091003c, u8,
  /// Output rate of the UBX-NAV-DOP message on port UART1
  MsgoutUbxNavDopUart1, 0x20910039, u8,
  /// Output rate of the UBX-NAV-EOE message on port I2C
  MsgoutUbxNavEoeI2c, 0x2091015f, u8,
  /// Output rate of the UBX-NAV-EOE message on port SPI
  MsgoutUbxNavEoeSpi, 0x20910163, u8,
  /// Output rate of the UBX-NAV-EOE message on port UART1
  MsgoutUbxNavEoeUart1, 0x20910160, u8,
  /// Output rate of the UBX-NAV-ODO message on port I2C
  MsgoutUbxNavOdoI2c, 0x2091007e, u8,
  /// Output rate of the UBX-NAV-ODO message on port SPI
  MsgoutUbxNavOdoSpi, 0x20910082, u8,
  /// Output rate of the UBX-NAV-ODO message on port UART1
  MsgoutUbxNavOdoUart1, 0x2091007f, u8,
  /// Output rate of the UBX-NAV-ORB message on port I2C
  MsgoutUbxNavOrbI2c, 0x20910010, u8,
  /// Output rate of the UBX-NAV-ORB message on port SPI
  MsgoutUbxNavOrbSpi, 0x20910014, u8,
  /// Output rate of the UBX-NAV-ORB message on port UART1
  MsgoutUbxNavOrbUart1, 0x20910011, u8,
  /// Output rate of the UBX-NAV-PL message on port I2C
  MsgoutUbxNavPlI2c, 0x20910415, u8,
  /// Output rate of the UBX-NAV-PL message on port SPI
  MsgoutUbxNavPlSpi, 0x20910419, u8,
  /// Output rate of the UBX-NAV-PL message on port UART1
  MsgoutUbxNavPlUart1, 0x20910416, u8,
  /// Output rate of the UBX-NAV-POSECEF message on port I2C
  MsgoutUbxNavPoseCefI2c, 0x20910024, u8,
  /// Output rate of the UBX-NAV-POSECEF message on port SPI
  MsgoutUbxNavPoseCefSpi, 0x20910028, u8,
  /// Output rate of the UBX-NAV-POSECEF message on port UART1
  MsgoutUbxNavPoseCefUart1, 0x20910025, u8,
  /// Output rate of the UBX-NAV-POSLLH message on port I2C
  MsgoutUbxNavPosLlhI2c, 0x20910029, u8,
  /// Output rate of the UBX-NAV-POSLLH message on port SPI
  MsgoutUbxNavPosLlhSpi, 0x2091002d, u8,
  /// Output rate of the UBX-NAV-POSLLH message on port UART1
  MsgoutUbxNavPosLlhUart1, 0x2091002a, u8,
  /// Output rate of the UBX-NAV-PVT message on port I2C
  MsgoutUbxNavPvtI2c, 0x20910006, u8,
  /// Output rate of the UBX-NAV-PVT message on port SPI
  MsgoutUbxNavPvtSpi, 0x2091000a, u8,
  /// Output rate of the UBX-NAV-PVT message on port UART1
  MsgoutUbxNavPvtUart1, 0x20910007, u8,
  /// Output rate of the UBX-NAV-SAT message on port I2C
  MsgoutUbxNavSatI2c, 0x20910015, u8,
  /// Output rate of the UBX-NAV-SAT message on port SPI
  MsgoutUbxNavSatSpi, 0x20910019, u8,
  /// Output rate of the UBX-NAV-SAT message on port UART1
  MsgoutUbxNavSatUart1, 0x20910016, u8,
  /// Output rate of the UBX-NAV-SBAS message on port I2C
  MsgoutUbxNavSbasI2c, 0x2091006a, u8,
  /// Output rate of the UBX-NAV-SBAS message on port SPI
  MsgoutUbxNavSbasSpi, 0x2091006e, u8,
  /// Output rate of the UBX-NAV-SBAS message on port UART1
  MsgoutUbxNavSbasUart1, 0x2091006b, u8,
  /// Output rate of the UBX-NAV-SIG message on port I2C
  MsgoutUbxNavSigI2c, 0x20910345, u8,
  /// Output rate of the UBX-NAV-SIG message on port SPI
  MsgoutUbxNavSigSpi, 0x20910349, u8,
  /// Output rate of the UBX-NAV-SIG message on port UART1
  MsgoutUbxNavSigUart1, 0x20910346, u8,
  /// Output rate of the UBX-NAV-SLAS message on port I2C
  MsgoutUbxNavSlasI2c, 0x20910336, u8,
  /// Output rate of the UBX-NAV-SLAS message on port SPI
  MsgoutUbxNavSlasSpi, 0x2091033a, u8,
  /// Output rate of the UBX-NAV-SLAS message on port UART1
  MsgoutUbxNavSlasUart1, 0x20910337, u8,
  /// Output rate of the UBX-NAV-STATUS message on port I2C
  MsgoutUbxNavStatusI2c, 0x2091001a, u8,
  /// Output rate of the UBX-NAV-STATUS message on port SPI
  MsgoutUbxNavStatusSpi, 0x2091001e, u8,
  /// Output rate of the UBX-NAV-STATUS message on port UART1
  MsgoutUbxNavStatusUart1, 0x2091001b, u8,
  /// Output rate of the UBX-NAV-TIMEBDS message on port I2C
  MsgoutUbxNavTimeBdsI2c, 0x20910051, u8,
  /// Output rate of the UBX-NAV-TIMEBDS message on port SPI
  MsgoutUbxNavTimeBdsSpi, 0x20910055, u8,
  /// Output rate of the UBX-NAV-TIMEBDS message on port UART1
  MsgoutUbxNavTimeBdsUart1, 0x20910052, u8,
  /// Output rate of the UBX-NAVTIMEGAL message on port I2C
  MsgoutUbxNavTimeGalI2c, 0x20910056, u8,
  /// Output rate of the UBX-NAVTIMEGAL message on port SPI
  MsgoutUbxNavTimeGalSpi, 0x2091005a, u8,
  /// Output rate of the UBX-NAVTIMEGAL message on port UART1
  MsgoutUbxNavTimeGalUart1, 0x20910057, u8,
  /// Output rate of the UBX-NAVTIMEGLO message on port I2C
  MsgoutUbxNavTimeGloI2c, 0x2091004c, u8,
  /// Output rate of the UBX-NAVTIMEGLO message on port SPI
  MsgoutUbxNavTimeGloSpi, 0x20910050, u8,
  /// Output rate of the UBX-NAVTIMEGLO message on port UART1
  MsgoutUbxNavTimeGloUart1, 0x2091004d, u8,
  /// Output rate of the UBX-NAV-TIMEGPS message on port I2C
  MsgoutUbxNavTimeGpsI2c, 0x20910047, u8,
  /// Output rate of the UBX-NAV-TIMEGPS message on port SPI
  MsgoutUbxNavTimeGpsSpi, 0x2091004b, u8,
  /// Output rate of the UBX-NAV-TIMEGPS message on port UART1
  MsgoutUbxNavTimeGpsUart1, 0x20910048, u8,
  /// Output rate of the UBX-NAV-TIMELS message on port I2C
  MsgoutUbxNavTimeLsI2c, 0x20910060, u8,
  /// Output rate of the UBX-NAV-TIMELS message on port SPI
  MsgoutUbxNavTimeLsSpi, 0x20910064, u8,
  /// Output rate of the UBX-NAV-TIMELS message on port UART1
  MsgoutUbxNavTimeLsUart1, 0x20910061, u8,
  /// Output rate of the UBX-NAV-TIMEQZSS message on port I2C
  MsgoutUbxNavTimeQzssI2c, 0x20910386, u8,
  /// Output rate of the UBX-NAV-TIMEQZSS message on port SPI
  MsgoutUbxNavTimeQzssSpi, 0x2091038a, u8,
  /// Output rate of the UBX-NAV-TIMEQZSS message on port UART1
  MsgoutUbxNavTimeQzssUart1, 0x20910387, u8,
  /// Output rate of the UBX-NAVTIMEUTC message on port I2C
  MsgoutUbxNavTimeUtcI2c, 0x2091005b, u8,
  /// Output rate of the UBX-NAVTIMEUTC message on port SPI
  MsgoutUbxNavTimeUtcSpi, 0x2091005f, u8,
  /// Output rate of the UBX-NAVTIMEUTC message on port UART1
  MsgoutUbxNavTimeUtcUart1, 0x2091005c, u8,
  /// Output rate of the UBX-NAV-VELECEF message on port I2C
  MsgoutUbxNavVelEcefI2c, 0x2091003d, u8,
  /// Output rate of the UBX-NAV-VELECEF message on port SPI
  MsgoutUbxNavVelEcefSpi, 0x20910041, u8,
  /// Output rate of the UBX-NAV-VELECEF message on port UART1
  MsgoutUbxNavVelEcefUart1, 0x2091003e, u8,
  /// Output rate of the UBX-NAV-VELNED message on port I2C
  MsgoutUbxNavVelNedI2c, 0x20910042, u8,
  /// Output rate of the UBX-NAV-VELNED message on port SPI
  MsgoutUbxNavVelNedSpi, 0x20910046, u8,
  /// Output rate of the UBX-NAV-VELNED message on port UART1
  MsgoutUbxNavVelNedUart1, 0x20910043, u8,
  /// Output rate of the UBX-RXM-MEAS20 message on port I2C
  MsgoutUbxRxmMeas20I2c, 0x20910643, u8,
  /// Output rate of the UBX-RXM-MEAS20 message on port SPI
  MsgoutUbxRxmMeas20Spi, 0x20910647, u8,
  /// Output rate of the UBX-RXM-MEAS20 message on port UART1
  MsgoutUbxRxmMeas20Uart1, 0x20910644, u8,
  /// Output rate of the UBX-RXM-MEAS50 message on port I2C
  MsgoutUbxRxmMeas50I2c, 0x20910648, u8,
  /// Output rate of the UBX-RXM-MEAS50 message on port SPI
  MsgoutUbxRxmMeas50Spi, 0x2091064c, u8,
  /// Output rate of the UBX-RXM-MEAS50 message on port UART1
  MsgoutUbxRxmMeas50Uart1, 0x20910649, u8,
  /// Output rate of the UBX-RXM-MEASC12 message on port I2C
  MsgoutUbxRxmMeasC12I2c, 0x2091063e, u8,
  /// Output rate of the UBX-RXM-MEASC12 message on port SPI
  MsgoutUbxRxmMeasC12Spi, 0x20910642, u8,
  /// Output rate of the UBX-RXM-MEASC12 message on port UART1
  MsgoutUbxRxmMeasC12Uart1, 0x2091063f, u8,
  /// Output rate of the UBX-RXM-MEASC12 message on port I2C
  MsgoutUbxRxmMeasD12I2c, 0x20910639, u8,
  /// Output rate of the UBX-RXM-MEASD12 message on port SPI
  MsgoutUbxRxmMeasD12Spi, 0x2091063d, u8,
  /// Output rate of the UBX-RXM-MEASD12 message on port UART1
  MsgoutUbxRxmMeasD12Uart1, 0x2091063a, u8,
  /// Output rate of the UBX-RXM-MEASX message on port I2C
  MsgoutUbxRxmMeasxI2c, 0x20910204, u8,
  /// Output rate of the UBX-RXM-MEASX message on port SPI
  MsgoutUbxRxmMeasxSpi, 0x20910208, u8,
  /// Output rate of the UBX-RXM-MEASX message on port UART1
  MsgoutUbxRxmMeasxUart1, 0x20910205, u8,
  /// Output rate of the UBX-RXM-RLM message on port I2C
  MsgoutUbxRxmRlmI2c, 0x2091025e, u8,
  /// Output rate of the UBX-RXM-RLM message on port SPI
  MsgoutUbxRxmRlmSpi, 0x20910262, u8,
  /// Output rate of the UBX-RXM-RLM message on port UART1
  MsgoutUbxRxmRlmUart1, 0x2091025f, u8,
  /// Output rate of the UBX-RXM-SFRBX message on port I2C
  MsgoutUbxRxmSfrbxI2c, 0x20910231, u8,
  /// Output rate of the UBX-RXM-SFRBX message on port SPI
  MsgoutUbxRxmSfrbxSpi, 0x20910235, u8,
  /// Output rate of the UBX-RXM-SFRBX message on port UART1
  MsgoutUbxRxmSfrbxUart1, 0x20910232, u8,
  /// Output rate of the UBX-TIM-TM2 message on port I2C
  MsgoutUbxTimTm2I2c, 0x20910178, u8,
  /// Output rate of the UBX-TIM-TM2 message on port SPI
  MsgoutUbxTimTm2Spi, 0x2091017c, u8,
  /// Output rate of the UBX-TIM-TM2 message on port UART1
  MsgoutUbxTimTm2Uart1, 0x20910179, u8,
  /// Output rate of the UBX-TIM-TP message on port I2C
  MsgoutUbxTimTpI2c, 0x2091017d, u8,
  /// Output rate of the UBX-TIM-TP message on port SPI
  MsgoutUbxTimTpSpi, 0x20910181, u8,
  /// Output rate of the UBX-TIM-TP message on port UART1
  MsgoutUbxTimTpUart1, 0x2091017e, u8,
  /// Output rate of the UBX-TIM-VRFY message on port I2C
  MsgoutUbxTimVrfyI2c, 0x20910092, u8,
  /// Output rate of the UBX-TIM-VRFY message on port SPI
  MsgoutUbxTimVrfySpi, 0x20910096, u8,
  /// Output rate of the UBX-TIM-VRFY message on port UART1
  MsgoutUbxTimVrfyUart1, 0x20910093, u8,

  // CFG-NAVSPG
  NavSpgFixMode, 0x20110011, FixMode,
  NavSpgInifix3D, 0x10110013, bool,
  NavSpgWknRollover, 0x30110017, u16,
  NavSpgUtcStandard, 0x2011001c, UtcStandard,
  NavSpgDynModel, 0x20110021, DynamicModel,
  NavSpgAckAiding, 0x10110025, bool,
  NavSpgUseUsrdat, 0x10110061, bool,
  NavSpgUsrDatMaja, 0x50110062, f64,
  NavSpgUsrDatFlat, 0x50110063, f64,
  NavSpgUsrDatDx, 0x40110064, f32,
  NavSpgUsrDatDy, 0x40110065, f32,
  NavSpgUsrDatDz, 0x40110066, f32,
  NavSpgUsrDatRotx, 0x40110067, f32,
  NavSpgUsrDatRoty, 0x40110068, f32,
  NavSpgUsrDatRotz, 0x40110069, f32,
  NavSpgUsrDatScale, 0x4011006a, f32,
  NavSpgInfilMinSvs, 0x201100a1, u8,
  NavSpgInfilMaxSvs, 0x201100a2, u8,
  NavSpgInfilMinCno, 0x201100a3, u8,
  NavSpgInfilMinElev, 0x201100a4, i8,
  NavSpgInfilNCnoThrs, 0x201100aa, u8,
  NavSpgInfilCnoThrs, 0x201100ab, u8,
  NavSpgOutfilPdop, 0x301100b1, u16,
  NavSpgOutfilTdop, 0x301100b2, u16,
  NavSpgOutfilPacc, 0x301100b3, u16,
  NavSpgOutfilTacc, 0x301100b4, u16,
  NavSpgOutfilFacc, 0x301100b5, u16,
  NavSpgConstrAlt, 0x401100c1, i32,
  NavSpgConstrAltVar, 0x401100c2, u32,
  NavSpgConstrDgnssto, 0x201100c4, u8,
//   NavSpgSigAttComp, 0x201100d6, SignalAttenuation,

  // CFG-NMEA
  NmeaProtVer, 0x20930001, ProtocolVersion,
  NmeaMaxSvs, 0x20930002, MaxSvs,
  NmeaCompat, 0x10930003, bool,
  NmeaConsider, 0x10930004, bool,
  NmeaLimit82, 0x10930005, bool,
  NmeaHighPrec, 0x10930006, bool,
  NmeaSvNumbering, 0x20930007, SatelliteNumbering,
  NmeaFiltGps, 0x10930011, bool,
  NmeaFiltSbas, 0x10930012, bool,
  NmeaFiltGal, 0x10930013, bool,
  NmeaFiltQzss, 0x10930015, bool,
  NmeaFiltGlo, 0x10930016, bool,
  NmeaFiltBds, 0x10930017, bool,
  NmeaOutInvfix, 0x10930021, bool,
  NmeaOutMskfix, 0x10930022, bool,
  NmeaOutInvtime, 0x10930023, bool,
  NmeaOutInvdate, 0x10930024, bool,
  NmeaOutOnlyGps, 0x10930025, bool,
  NmeaOutFrozenCog, 0x10930026, bool,
  NmeaMainTalkerId, 0x20930031, MainTalkerId,
  NmeaGsvTalkerId, 0x20930032, GsvTalkerId,
  NmeaBdsTalkerId, 0x30930033, u16,

  // CFG-ODO
  OdoUseOdo, 0x10220001, bool,
  OdoUseCog, 0x10220002, bool,
  OdoOutLpVel, 0x10220003, bool,
  OdoOutLpCog, 0x10220004, bool,
  OdoProfile, 0x20220005, OdometerProfile,
  OdoCogMaxSpeed, 0x20220021, u8,
  OdoCogMaxPossAcc, 0x20220022, u8,
  OdoVelLpGain, 0x20220031, u8,
  OdoCogLpGain, 0x20220032, u8,

  // CFG-PM
  PmOperateMode, 0x20d00001, PmOperationMode,
  PmPosUpdatePeriod, 0x40d00002, u32,
  PmAcqPeriod, 0x40d00003, u32,
  PmGridOffset, 0x40d00004, u32,
  PmOnTime, 0x30d00005, u16,
  PmMinAcqTime, 0x20d00006, u8,
  PmMaxAcqTime, 0x20d00007, u8,
  PmDoNotEnterOff, 0x10d00008, bool,
  PmWaitTimeFix, 0x10d00009, bool,
  PmUpdateEph, 0x10d0000a, bool,
  PmExtIntWake, 0x10d0000c, bool,
  PmExtIntBackup, 0x10d0000d, bool,
  PmExtIntActive, 0x10d0000e, bool,
  PmExtIntInactivity, 0x40d0000f, u32,
  PmLimitPeakCurr, 0x10d00010, bool,

  // CFG-QZSS
  QzssUseSlasDgnss, 0x10370005, bool,
  QzssUseSlasTestMode, 0x10370006, bool,
  QzssUseSlasRaimUncorr, 0x10370007, bool,
  QzssSlasMaxBaseline, 0x30370008, u16,

  // CFG-RATE-*
  /// Nominal time between GNSS measurements
  /// (e.g. 100ms results in 10Hz measurement rate, 1000ms = 1Hz measurement rate)
  RateMeas,              0x30210001, u16,
  /// Ratio of number of measurements to number of navigation solutions
  RateNav,               0x30210002, u16,
  /// Time system to which measurements are aligned
  RateTimeref,           0x20210003, TimeReference,

  // CFG-RINV
  RinvDump, 0x10c70001, bool,
  RinvBinary, 0x10c70002, bool,
  RinvDataSize, 0x20c70003, u8,
  RinvChunk0, 0x50c70004, u64,
  RinvChunk1, 0x50c70005, u64,
  RinvChunk2, 0x50c70006, u64,
  RinvChunk3, 0x50c70007, u64,

  // CFG-SBAS
  SbasUseTestMode, 0x10360002, bool,
  SbasUseRanging, 0x10360003, bool,
  SbasUseDiffCorr, 0x10360004, bool,
  SbasUseIntegrity, 0x10360005, bool,
  SbasPrnScanMask, 0x50360006, u64,

  // CFG-SEC
  SecCfgLock, 0x10f60009, bool,
  SecCfgLockUnlockGrp1, 0x30f6000a, u16,
  SecCfgLockUnlockGrp2, 0x30f6000b, u16,

  // CFG-SIGNAL-*
  SignalGpsEna,          0x1031001f, bool,
  SignalGpsL1caEna,      0x10310001, bool,
  SignalSbasEna,         0x10310020, bool,
  SignalSbasL1caEna,     0x10310005, bool,
  SignalGalEna,          0x10310021, bool,
  SignalGalE1Ena,        0x10310007, bool,
  SignalBdsEna,          0x10310022, bool,
  SignalBdsB1Ena,        0x1031000d, bool,
  SignalBdsB1cEna,       0x1031000f, bool,
  SignalQzssEna,         0x10310024, bool,
  SignalQzssL1caEna,     0x10310012, bool,
  SignalQzssL1sEna,      0x10310014, bool,
  SignalGloEna,          0x10310025, bool,
  SignalGloL1Ena,        0x10310018, bool,

  // CFG-SPI
  SpiMaxff, 0x20640001, u8,
  SpiCPolarity, 0x10640002, bool,
  SpiCPhase, 0x10640003, bool,
  SpiExtendedTimeout, 0x10640005, bool,
  SpiEnabled, 0x10640006, bool,

  // CFG-SPIINPROT
  SpiInProtUbx, 0x10790001, bool,
  SpiInProtNmea, 0x10790002, bool,

  // CFG-SPIOUTPROT
  SpiOutProtUbx, 0x107a0001, bool,
  SpiOutProtNmea, 0x107a0002, bool,

    // CFG-TP-*
  TpPulseDef,            0x20050023, TpPulse,
  TpPulseLengthDef,      0x20050030, TpPulseLength,
  TpAntCableDelay,       0x30050001, i16,
  TpPeriodTp1,           0x40050002, u32,
  TpPeriodLockTp1,       0x40050003, u32,
  TpFreqTp1,             0x40050024, u32,
  TpFreqLockTp1,         0x40050025, u32,
  TpLenTp1,              0x40050004, u32,
  TpLenLockTp1,          0x40050005, u32,
  TpDutyTp1,             0x5005002a, f64,
  TpDutyLockTp1,         0x5005002b, f64,
  TpUserDelay,           0x40050006, i32,
  TpTp1Ena,              0x10050007, bool,
  TpSyncGnssTp1,         0x10050008, bool,
  TpUseLockedTp1,        0x10050009, bool,
  TpAlignToTowTp1,       0x1005000a, bool,
  TpPolTp1,              0x1005000b, bool,
  TpTimegridTp1,         0x2005000c, TimeReference,

  // CFG-TXREADY
  TxReadyEnabled, 0x10a20001, bool,
  TxReadyPolarity, 0x10a20002, bool,
  TxReadyPin, 0x20a20003, u8,
  TxReadyThreshold, 0x30a20004, u16,
  TxReadyInterface, 0x20a20005, TXReadyInterface,

  // CFG-UART1
  Uart1Baudrate,        0x40520001, u32,
  Uart1StopBits,        0x20520002, StopBits,
  Uart1DataBits,        0x20520003, DataBits,
  Uart1Parity,          0x20520004, Parity,
  Uart1Enabled,         0x10520005, bool,

  // CFG-UART1INPROT
  Uart1InProtUbx,       0x10730001, bool,
  Uart1InProtNmea,      0x10730002, bool,

  // CFG-UART1OUTPROT
  Uart1OutProtUbx,       0x10740001, bool,
  Uart1OutProtNmea,      0x10740002, bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpPulse {
    /// Time pulse period
    Period = 0,
    /// Time pulse frequency
    Freq = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpPulseLength {
    /// Time pulse ratio
    Ratio = 0,
    /// Time pulse length
    Length = 1,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum EngineSelection {
    Ext = 0,
    Madc = 1,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum LnaMode {
    Normal = 0,
    LowGain = 1,
    Bypass = 2,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum AntennaSetting {
    Unknown = 0,
    Passive = 1,
    Active = 2,
}

/// Nav position fix mode
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum FixMode {
    TwoDOnly = 0,
    ThreeDOnly = 1,
    Auto = 2,
}

/// UTC Standard
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum UtcStandard {
    Auto = 0,
    USNO = 3,
    EU = 5,
    SU = 6,
    NTSC = 7,
    NPLI = 8,
    NICT = 9,
}

/// UTC Standard
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DynamicModel {
    Portable = 0,
    Stationary = 2,
    Pedestrian = 3,
    Automotive = 4,
    Sea = 5,
    Air1 = 6,
    Air2 = 7,
    Air4 = 8,
    Wrist = 9,
    Bike = 10,
    Mower = 11,
    Escooter = 12,
}

/// UTC Standard
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum SignalAttenuation {
    Disabled = 0,
    Auto = 255,
    One = 1,
    Two,
    Sea,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ProtocolVersion {
    V21 = 21,
    V23 = 23,
    V40 = 40,
    V41 = 41,
    V411 = 42,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum MaxSvs {
    Unlim = 0,
    Eight = 8,
    Twelve = 12,
    Sixteen = 16,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum SatelliteNumbering {
    Strict = 0,
    Extended = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum MainTalkerId {
    Auto = 0,
    Gp = 1,
    Gl = 2,
    Gn = 3,
    Ga = 4,
    Gb = 5,
    Gq = 7,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum GsvTalkerId {
    Gnss = 0,
    Main = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum OdometerProfile {
    Running = 0,
    Cycling = 1,
    Swimming = 2,
    Car = 3,
    Custom = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PmOperationMode {
    Full = 0,
    PsmOO = 1,
    PmsCT = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum TimeReference {
    Utc = 0,
    Gps = 1,
    Glo = 2,
    Bds = 3,
    Gal = 4,
    Navic = 5,
    Local = 15,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum TXReadyInterface {
    I2c = 0,
    Spi = 1,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum StopBits {
    Half = 0,
    One = 1,
    OneHalf = 2,
    Two = 3,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DataBits {
    Eight = 0,
    Seven = 1,
}

/// Hw engine selection
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Parity {
    None = 0,
    Odd = 1,
    Even = 2,
}
