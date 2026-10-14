// Minimal ambient declarations (avoids a dependency on @types/chrome).
declare const chrome: any;
declare var module: any;
declare var IW_RULES: IwRuleConfig;

interface IwRule { id: string; lang: string; category: string; weight: number; standalone: boolean; pattern: string; desc: string; needs_context?: boolean; }
interface IwRuleConfig {
  version: string; threshold: number; combo_bonus: number;
  location_factors: Record<string, number>; in_code_factor: number; hidden_in_code_factor: number;
  discussion_factor: number; hidden_discussion_factor: number; mention_factor: number;
  mention_min_outside_chars: number; zero_width_min_factor: number; non_counting_categories: string[];
  context_categories?: string[]; single_count_categories?: string[]; blob_min_json_pairs?: number; blob_min_spintax?: number;
  discussion_pattern: string; quote_pattern: string; rules: IwRule[];
}
interface IwCandidate { text: string; location: string; techniques: string[]; path: string; in_code?: boolean; }
interface IwFinding {
  payload_hash: string; category: string; intent: string; location: string; technique: string;
  score: number; excerpt: string; rules: string[];
}
declare function injectionwatchHiddenText(doc: Document): { candidates: IwCandidate[] };
