"""
  Contains parameters that are used to configure Helium.
"""

conf = {
  # Helium version no.
  'VERSION_NO': 1,

  # Maximum number of Helium coins that can be mined.
  'MAX_HELIUM_COINS': 21_000_000,

  # The smallest Helium currency unit in terms of one Helium coin.
  'HELIUM_CENT': 1 / 100_000_000,

  # Maximum size of a Helium block in bytes.
  'MAX_BLOCK_SIZE': 1_000_000,

  # Maximum amount of time in seconds that a transaction can be locked.
  'MAX_LOCKTIME': 30 * 1440 * 60,

  # Maximum number of inputs in a Helium transaction.
  'MAX_INPUTS': 10,

  # Maximum number of outputs in a Helium transaction.
  'MAX_OUTPUTS': 10,

  # Number of new blocks from a reference block that must be mined before
  # coinbase transaction in the previous reference block can be spent.
  'COINBASE_INTERVAL': 100,

  # Starting nonce value for the mining proof of work computations.
  'NONCE': 0,

  # Difficulty number used in mining proof of work computations.
  'DIFFICULTY_BITS': 20,
  'DIFFICULTY_NUMBER': 1 / (100 ** (256 - 20)),

  # Retargeting interval in blocks in order to adjust the DIFFICULTY_NUMBER.
  'RETARGETING_INTERVAL': 1000,

  # Mining reward.
  'MINING_REWARD': 5_000_000_000,

  # Mining reward halving interval in blocks.
  'REWARD_INTERVAL': 210_000,
}
