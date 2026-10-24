export interface VaultDetail extends VaultSummary {
  currentEpoch: number;
  currentPhase: EpochPhase;
  phaseEndsAt: string; // ISO — when the current phase ends
  sharePrice: number;
  totalShares: number;
  payoffExplanation: string;
  queue: QueueState;
  fees: FeeAccrual;
  recentEpochs: EpochRecord[];
  userPosition: UserVaultPosition | null;
  /** Shadow (paper-trading) state, present only for `mode: "shadow"` vaults. */
  shadow?: ShadowState;
  /** Promotion criteria for shadow strategies. */
  promotionCriteria?: PromotionCriteria;
  /** Inflation / donation-attack defense parameters. */
  inflationDefense?: InflationDefenseConfig;
}
