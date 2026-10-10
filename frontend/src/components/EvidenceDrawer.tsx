// COUNTERSIGN — Evidence Drawer
// Standalone component displaying verification evidence from existing VerifyResponse fields
// Uses only backend-exposed data — no invented fields

import { useState, useEffect } from 'react';
import { X, Copy, Key, Hash, Brain, Gavel, Shield, Info, AlertTriangle } from 'lucide-react';
import type { VerifyResponse, CryptographicEvidenceMetadata, Grounding, PolicyResult } from '@/types/api';

type EvidenceTab = 'cryptographic' | 'ai' | 'policy' | 'metadata';

interface TabConfig {
  id: EvidenceTab;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  description: string;
}

const TABS: TabConfig[] = [
  {
    id: 'cryptographic',
    label: 'Cryptographic',
    icon: Shield,
    description: 'Authoritative Ed25519 verification — trust directory & replay protection',
  },
  {
    id: 'ai',
    label: 'AI Interpretation',
    icon: Brain,
    description: 'Untrusted sensor output — AI-extracted claims with grounding',
  },
  {
    id: 'policy',
    label: 'Policy',
    icon: Gavel,
    description: 'Deterministic evaluation of AI-extracted action',
  },
  {
    id: 'metadata',
    label: 'Metadata',
    icon: Info,
    description: 'Request identity, verdict, and backend explanation',
  },
];

function TabButton({ tab, isActive, onClick }: { tab: TabConfig; isActive: boolean; onClick: () => void }) {
  const Icon = tab.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
        isActive
          ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
          : 'text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800 hover:text-neutral-900 dark:hover:text-neutral-100'
      }`}
      aria-selected={isActive}
    >
      <Icon size={16} aria-hidden="true" />
      {tab.label}
    </button>
  );
}

function formatClaimValue(value: unknown): string {
  if (value === null) return 'Not extracted';
  if (value === undefined) return 'Not available';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') {
    if (Array.isArray(value)) {
      return value.map((v) => formatClaimValue(v)).join(', ');
    }
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([_, v]) => v !== undefined && v !== null
    );
    if (entries.length === 0) return 'Not extracted';
    return entries
      .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      .join(', ');
  }
  return String(value);
}

function KeyValueRow({ label, value, copyable = false }: { label: string; value: unknown; copyable?: boolean }) {
  const displayValue = typeof value === 'string' ? value : formatClaimValue(value);
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700">
      <span className="text-xs font-medium text-neutral-500 dark:text-neutral-400 font-mono min-w-[140px] shrink-0">{label}</span>
      <span className="flex-1 text-sm font-mono text-neutral-900 dark:text-neutral-100 break-all">{displayValue}</span>
      {copyable && (
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(displayValue)}
          className="p-1.5 rounded hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors flex-shrink-0"
          aria-label={`Copy ${label}`}
        >
          <Copy size={14} className="text-neutral-500 dark:text-neutral-400" />
        </button>
      )}
    </div>
  );
}

function SectionHeader({ icon: Icon, title, description }: { icon: React.ComponentType<{ size?: number; className?: string }>; title: string; description?: string }) {
  return (
    <div className="mb-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={16} className="text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <h4 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400">{title}</h4>
      </div>
      {description && <p className="text-xs text-neutral-500 dark:text-neutral-400 ml-6">{description}</p>}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="text-center py-8 text-neutral-500 dark:text-neutral-400 text-sm">
      {message}
    </div>
  );
}

function CryptographicTab({ evidence }: { evidence: VerifyResponse['cryptographic_evidence'] }) {
  const { verified_fields, signed_values, metadata } = evidence;

  return (
    <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
      {/* Verified Fields */}
      <SectionHeader icon={Key} title="Verified Fields" description="Fields cryptographically bound to the signature" />
      {verified_fields.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {verified_fields.map((field, idx) => (
            <span
              key={idx}
              className="px-3 py-1.5 rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-sm font-mono border border-emerald-300 dark:border-emerald-700"
            >
              {field}
            </span>
          ))}
        </div>
      ) : (
        <EmptyState message="No fields were cryptographically verified by the backend." />
      )}

      {/* Signed Values */}
      <SectionHeader icon={Hash} title="Signed Values" description="Exact values included in the cryptographic signature" />
      {Object.keys(signed_values).length > 0 ? (
        <div className="space-y-2">
          {Object.entries(signed_values).map(([key, value]) => (
            <KeyValueRow key={key} label={key} value={value} copyable />
          ))}
        </div>
      ) : (
        <EmptyState message="No signed values returned by the backend." />
      )}

      {/* Metadata */}
      <SectionHeader icon={Info} title="Verification Metadata" description="Context from the trust directory and verification process" />
      <div className="space-y-2">
        {(Object.entries(metadata) as [keyof CryptographicEvidenceMetadata, string | number | undefined][]).map(([key, value]) => (
          value !== undefined && value !== null ? (
            <KeyValueRow key={key} label={key} value={String(value)} />
          ) : null
        ))}
      </div>
    </div>
  );
}

function formatGrounding(grounding: Grounding | null): string {
  if (!grounding) return 'No grounding available';
  return `chars ${grounding.start}–${grounding.end} (${grounding.type})`;
}


function AITab({ ai }: { ai: VerifyResponse['ai_interpretation'] }) {
  const { trusted, status, claims } = ai;

  return (
    <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
      {/* Trust Indicator */}
      <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800">
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangle size={16} className="text-amber-600 dark:text-amber-400" aria-hidden="true" />
          <span className="text-sm font-semibold text-amber-700 dark:text-amber-300">UNTRUSTED SENSOR OUTPUT</span>
        </div>
        <p className="text-xs text-amber-600 dark:text-amber-400">
          AI interpretations are sensor readings, not evidence. Only cryptographic verification is authoritative.
        </p>
      </div>

      {/* Trust Field */}
      <SectionHeader icon={Shield} title="Trust Status" />
      <div className="space-y-2">
        <KeyValueRow key="trusted" label="trusted" value={String(trusted)} />
      </div>

      {/* Status */}
      <SectionHeader icon={Brain} title="Interpretation Status" />
      <div className="space-y-2">
        <KeyValueRow key="status" label="status" value={status.replace(/_/g, ' ').toUpperCase()} />
      </div>

      {/* Extracted Claims */}
      <SectionHeader icon={Brain} title="Extracted Claims" description="AI-extracted fields from input text (untrusted)" />
      <div className="space-y-2">
        <KeyValueRow key="organization" label="organization" value={formatClaimValue(claims.organization)} />
        <KeyValueRow key="requested_action" label="requested_action" value={formatClaimValue(claims.requested_action)} />
        <KeyValueRow key="payment_claim" label="payment_claim" value={formatClaimValue(claims.payment_claim)} />
        <KeyValueRow key="suspicious_instruction" label="suspicious_instruction" value={formatClaimValue(claims.suspicious_instruction)} />
        <KeyValueRow key="confidence" label="confidence" value={`${(claims.confidence * 100).toFixed(1)}%`} />
        <KeyValueRow key="grounding" label="grounding" value={formatGrounding(claims.grounding)} />
      </div>
    </div>
  );
}

function PolicyTab({ policy }: { policy: PolicyResult }) {
  const { evaluated, result, error_code } = policy;

  return (
    <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
      {/* Evaluation Status */}
      <SectionHeader icon={Gavel} title="Policy Evaluation" description="Deterministic result from policy engine" />
      <div className="space-y-2">
        <KeyValueRow key="evaluated" label="evaluated" value={evaluated ? 'Yes' : 'No'} />
        {evaluated && result && (
          <KeyValueRow key="result" label="result" value={result} />
        )}
        {error_code && (
          <KeyValueRow key="error_code" label="error_code" value={error_code} />
        )}
      </div>

      {/* Policy Logic Note */}
      <div className="p-4 rounded-lg bg-sky-50 dark:bg-sky-950/20 border border-sky-200 dark:border-sky-800">
        <p className="text-sm text-sky-700 dark:text-sky-300">
          Policy evaluation is <span className="font-semibold">deterministic</span> — same AI-extracted action always yields same result.
          Contradictions indicate the AI interpretation conflicts with allowed actions, not a cryptographic failure.
        </p>
      </div>
    </div>
  );
}

function MetadataTab({ response }: { response: VerifyResponse }) {
  const { request_id, verdict, error_code, explanation, cryptographic_evidence } = response;

  return (
    <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
      {/* Request Identity */}
      <SectionHeader icon={Shield} title="Request Identity" />
      <div className="space-y-2">
        <KeyValueRow key="request_id" label="request_id" value={request_id} copyable />
        <KeyValueRow key="verdict" label="verdict" value={verdict} />
        {error_code && <KeyValueRow key="error_code" label="error_code" value={error_code} />}
      </div>

      {/* Backend Explanation */}
      <SectionHeader icon={Info} title="Backend Explanation" />
      <div className="p-4 rounded-lg bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700">
        <p className="text-sm text-neutral-900 dark:text-neutral-100 whitespace-pre-wrap">{explanation}</p>
      </div>

      {/* Verification Time (from crypto metadata if available) */}
      {cryptographic_evidence.metadata.verification_time && (
        <>
          <SectionHeader icon={Info} title="Verification Timestamp" />
          <div className="space-y-2">
            <KeyValueRow key="verification_time" label="verification_time" value={cryptographic_evidence.metadata.verification_time} />
          </div>
        </>
      )}
    </div>
  );
}

export function EvidenceDrawer({ response, open, onClose }: { response: VerifyResponse; open: boolean; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState<EvidenceTab>('cryptographic');

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    if (open) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="evidence-drawer-title">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Panel */}
      <div
        className="relative w-full max-w-3xl max-h-[85vh] bg-white dark:bg-neutral-950 rounded-2xl border border-neutral-200 dark:border-neutral-800 shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-neutral-200 dark:border-neutral-800 flex-shrink-0">
          <h2 id="evidence-drawer-title" className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Verification Evidence
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
            aria-label="Close evidence drawer"
          >
            <X size={20} className="text-neutral-500 dark:text-neutral-400" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-1 p-2 border-b border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 flex-shrink-0 overflow-x-auto">
          {TABS.map((tab) => (
            <TabButton key={tab.id} tab={tab} isActive={activeTab === tab.id} onClick={() => setActiveTab(tab.id)} />
          ))}
        </div>

        {/* Tab Description */}
        <div className="px-4 py-2 bg-neutral-50 dark:bg-neutral-900/50 border-b border-neutral-200 dark:border-neutral-800 flex-shrink-0">
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            {TABS.find((t) => t.id === activeTab)?.description}
          </p>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-hidden">
          <div className="p-4 overflow-y-auto" role="tabpanel" aria-labelledby="evidence-drawer-title">
            {activeTab === 'cryptographic' && <CryptographicTab evidence={response.cryptographic_evidence} />}
            {activeTab === 'ai' && <AITab ai={response.ai_interpretation} />}
            {activeTab === 'policy' && <PolicyTab policy={response.policy} />}
            {activeTab === 'metadata' && <MetadataTab response={response} />}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-neutral-200 dark:border-neutral-800 flex-shrink-0">
          <p className="text-xs text-neutral-500 dark:text-neutral-400 text-center">
            Source: COUNTERSIGN backend /verify endpoint — all fields from authoritative response
          </p>
        </div>
      </div>
    </div>
  );
}