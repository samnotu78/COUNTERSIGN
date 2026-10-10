// COUNTERSIGN — Visual Foundation + Step 5 Verification
// Single coherent security instrument: Hero + Verification Pipeline + Scenario Selection + Verification Flow

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import {
  FileText,
  Brain,
  ShieldCheck,
  Gavel,
  Shield,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Loader2,
  ChevronUp,
  AlertCircle,
  Key,
  Hash,
  Copy,
} from 'lucide-react';
import { verifyFixture } from '@/lib/api';
import type { VerifyResponse, FixtureId } from '@/types/api';
import { EvidenceDrawer } from '@/components/EvidenceDrawer';
import './App.css';

const pipelineStages: PipelineStageData[] = [
  {
    id: 'claim',
    label: 'CLAIM',
    description: 'Untrusted input text or signed token',
    icon: FileText,
    variant: 'neutral',
  },
  {
    id: 'ai',
    label: 'AI INTERPRETATION',
    description: 'Extracted claims — untrusted sensor output',
    icon: Brain,
    variant: 'ai',
  },
  {
    id: 'crypto',
    label: 'CRYPTOGRAPHIC VERIFICATION',
    description: 'Ed25519 signature • Trust directory • Replay protection',
    icon: ShieldCheck,
    variant: 'crypto',
  },
  {
    id: 'policy',
    label: 'POLICY',
    description: 'Deterministic evaluation of AI-extracted action',
    icon: Gavel,
    variant: 'policy',
  },
  {
    id: 'verdict',
    label: 'VERDICT',
    description: 'VERIFIED • CONTRADICTS_POLICY • UNVERIFIABLE',
    icon: Shield,
    variant: 'verdict',
  },
] as const;

type StageVariant = 'neutral' | 'ai' | 'crypto' | 'policy' | 'verdict';

const variantStyles: Record<StageVariant, string> = {
  neutral: 'border-neutral-300 dark:border-neutral-700',
  ai: 'border-amber-400 dark:border-amber-500 bg-amber-50 dark:bg-amber-950/20',
  crypto: 'border-emerald-400 dark:border-emerald-500 bg-emerald-50 dark:bg-emerald-950/20',
  policy: 'border-sky-400 dark:border-sky-500 bg-sky-50 dark:bg-sky-950/20',
  verdict: 'border-neutral-400 dark:border-neutral-600 bg-neutral-50 dark:bg-neutral-900/50',
};

const variantIconColors: Record<StageVariant, string> = {
  neutral: 'text-neutral-500 dark:text-neutral-400',
  ai: 'text-amber-600 dark:text-amber-400',
  crypto: 'text-emerald-600 dark:text-emerald-400',
  policy: 'text-sky-600 dark:text-sky-400',
  verdict: 'text-neutral-600 dark:text-neutral-400',
};

const variantLabels: Record<StageVariant, { text: string; className: string }> = {
  neutral: { text: 'INPUT', className: 'bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300' },
  ai: { text: 'UNTRUSTED', className: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300' },
  crypto: { text: 'AUTHORITATIVE', className: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' },
  policy: { text: 'DETERMINISTIC', className: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300' },
  verdict: { text: 'FINAL', className: 'bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300' },
};

interface PipelineStageData {
  id: string;
  label: string;
  description: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  variant: StageVariant;
}

function StageIcon({ icon: Icon, variant, size = 28 }: { icon: React.ComponentType<{ size?: number; className?: string }>; variant: StageVariant; size?: number }) {
  return (
    <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-white dark:bg-neutral-900 border-2 shadow-sm" style={{ borderColor: variant === 'neutral' ? 'transparent' : 'currentColor' }}>
      <Icon size={size} className={variantIconColors[variant]} />
    </div>
  );
}

type VerificationState = 'IDLE' | 'VERIFYING' | 'COMPLETED' | 'ERROR';

interface Scenario {
  id: FixtureId;
  label: string;
  description: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  variant: StageVariant;
}

const scenarios: Scenario[] = [
  {
    id: 'valid',
    label: 'VALID REQUEST',
    description: 'Matching signed token and input — should verify',
    icon: CheckCircle2,
    variant: 'crypto',
  },
  {
    id: 'tampered',
    label: 'TAMPERED REQUEST',
    description: 'Signature intact but amount mutated post-signing',
    icon: AlertTriangle,
    variant: 'ai',
  },
  {
    id: 'compromised_ai',
    label: 'COMPROMISED AI',
    description: 'Malicious instruction injected into input text',
    icon: Brain,
    variant: 'ai',
  },
  {
    id: 'contradictory_claim',
    label: 'CONTRADICTORY CLAIM',
    description: 'Input requests OTP disclosure; token says payment',
    icon: Gavel,
    variant: 'policy',
  },
  {
    id: 'ungrounded_ai',
    label: 'UNGROUNDED AI',
    description: 'AI extracts fictional claim without textual support',
    icon: HelpCircle,
    variant: 'verdict',
  },
] as const;

function PipelineStage({ stage, index, isLast }: { stage: PipelineStageData; index: number; isLast: boolean }) {
  const variant = stage.variant;
  const label = variantLabels[variant];

  return (
    <div className="flex flex-col items-center relative stage-animate" style={{ animationDelay: `${index * 100}ms` }}>
      {/* Vertical connector line */}
      {index > 0 && (
        <div className="absolute left-1/2 -translate-x-1/2 top-[-24px] w-0.5 h-12 bg-neutral-300 dark:bg-neutral-700" />
      )}

      {/* Stage Card */}
      <div className={`relative w-full max-w-sm ${variantStyles[variant]} rounded-2xl border-2 p-6 transition-all duration-300 hover:shadow-lg`}>
        {/* Stage Label Badge */}
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <span className={`${label.className} text-xs font-semibold px-3 py-1 rounded-full border border-current`}>
            {label.text}
          </span>
        </div>

        {/* Icon */}
        <div className="flex justify-center mb-4">
          <StageIcon icon={stage.icon} variant={variant} />
        </div>

        {/* Stage Label */}
        <h3 className="text-lg font-semibold text-center text-neutral-900 dark:text-neutral-100 mb-2">
          {stage.label}
        </h3>

        {/* Description */}
        <p className="text-sm text-neutral-600 dark:text-neutral-400 text-center leading-relaxed">
          {stage.description}
        </p>
      </div>

      {/* Arrow to next stage */}
      {!isLast && (
        <div className="flex items-center justify-center w-full h-12">
          <ArrowRight size={24} className="text-neutral-400 dark:text-neutral-500" />
        </div>
      )}
    </div>
  );
}

function Hero() {
  return (
    <header className="relative py-20 lg:py-28 px-4 hero-animate">
      <div className="max-w-5xl mx-auto text-center">
        {/* Eyebrow */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-neutral-100 dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 mb-6">
          <span className="text-xs font-medium tracking-wider text-neutral-700 dark:text-neutral-300">
            COUNTERSIGN / TRUST VERIFICATION
          </span>
        </div>

        {/* Headline */}
        <h1 className="text-4xl lg:text-5xl xl:text-6xl font-semibold leading-[1.1] text-neutral-950 dark:text-neutral-50 mb-6">
          AI interprets the request.
          <br />
          <span className="text-emerald-600 dark:text-emerald-400">
            Cryptography decides whether you can trust it.
          </span>
        </h1>

        {/* Supporting Text */}
        <p className="text-lg lg:text-xl text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          An AI-assisted verification system where AI can interpret a request,
          but cryptographic evidence remains authoritative.
        </p>

        {/* Primary CTA */}
        <div className="flex items-center justify-center gap-4 flex-wrap">
          <Button size="lg" className="gap-2 px-8 py-3.5 text-base font-medium">
            <ShieldCheck size={20} />
            VERIFY A SCENARIO
          </Button>
        </div>
      </div>
    </header>
  );
}

function VerificationPipeline() {
  return (
    <section className="py-16 lg:py-24 px-4" aria-labelledby="pipeline-heading">
      <div className="max-w-7xl mx-auto">
        <h2 id="pipeline-heading" className="sr-only">Verification Pipeline</h2>

        <div className="relative">
          {/* Horizontal connector line (desktop) */}
          <div className="hidden lg:block absolute top-[85px] left-[70px] right-[70px] h-0.5 bg-neutral-200 dark:bg-neutral-700" />

          <div className="flex flex-col lg:flex-row items-center justify-center gap-4 lg:gap-0">
            {pipelineStages.map((stage, index) => (
              <PipelineStage
                key={stage.id}
                stage={stage}
                index={index}
                isLast={index === pipelineStages.length - 1}
              />
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="mt-16 flex flex-wrap items-center justify-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-amber-100 dark:bg-amber-900/30 border border-amber-400 dark:border-amber-500" />
            <span className="text-neutral-600 dark:text-neutral-400">AI = Untrusted sensor</span>
          </div>
          <Separator orientation="vertical" className="h-5 bg-neutral-300 dark:bg-neutral-700" />
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-emerald-100 dark:bg-emerald-900/30 border border-emerald-400 dark:border-emerald-500" />
            <span className="text-neutral-600 dark:text-neutral-400">Cryptography = Authoritative</span>
          </div>
          <Separator orientation="vertical" className="h-5 bg-neutral-300 dark:bg-neutral-700" />
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-sky-100 dark:bg-sky-900/30 border border-sky-400 dark:border-sky-500" />
            <span className="text-neutral-600 dark:text-neutral-400">Policy = Deterministic</span>
          </div>
        </div>
      </div>
    </section>
  );
}

function SecurityLegend() {
  const items = [
    { icon: CheckCircle2, color: 'text-emerald-600 dark:text-emerald-400', label: '✓ = Cryptographically verified — signed by issuer' },
    { icon: AlertTriangle, color: 'text-amber-600 dark:text-amber-400', label: '⚠ = AI interpretation — untrusted sensor output' },
    { icon: HelpCircle, color: 'text-neutral-500 dark:text-neutral-400', label: '? = Unverifiable — insufficient cryptographic evidence' },
  ];

  return (
    <footer className="py-12 px-4 border-t border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950/50 legend-animate">
      <div className="max-w-5xl mx-auto">
        <h3 className="text-sm font-semibold text-neutral-700 dark:text-neutral-300 mb-6 uppercase tracking-wider">
          Security Model Legend
        </h3>
        <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {items.map((item, index) => (
            <div key={index} className="flex items-start gap-3">
              <item.icon size={18} className={`mt-1 flex-shrink-0 ${item.color}`} aria-hidden="true" />
              <dd className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
                {item.label}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </footer>
  );
}

function ScenarioCard({ scenario, isSelected, onSelect }: { scenario: Scenario; isSelected: boolean; onSelect: () => void }) {
  const variant = scenario.variant;
  const label = variantLabels[variant];

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`relative w-full text-left p-5 rounded-xl border-2 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 ${
        isSelected
          ? `${variantStyles[variant]} ring-2 ring-current border-current shadow-lg`
          : `${variantStyles[variant]} border-current/50 hover:border-current/75 hover:shadow-md`
      }`}
      aria-pressed={isSelected}
    >
      <div className="flex items-start gap-4">
        <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-white dark:bg-neutral-900 border border-current/50 flex-shrink-0">
          <scenario.icon size={22} className={variantIconColors[variant]} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`${label.className} text-xs font-semibold px-2.5 py-0.5 rounded border border-current`}>
              {label.text}
            </span>
          </div>
          <h4 className="font-semibold text-neutral-900 dark:text-neutral-100 mb-1 truncate">
            {scenario.label}
          </h4>
          <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {scenario.description}
          </p>
        </div>
        {isSelected && (
          <div className="flex items-center justify-center w-8 h-8 rounded-full bg-current text-white flex-shrink-0">
            <CheckCircle2 size={16} />
          </div>
        )}
      </div>
    </button>
  );
}

function VerdictPanel({ state, response, error, onOpenEvidence }: { state: VerificationState; response: VerifyResponse | null; error: Error | null; onOpenEvidence: () => void }) {
  if (state === 'IDLE') {
    return (
      <div className="w-full rounded-2xl border-2 border-neutral-300 dark:border-neutral-700 p-8 transition-all duration-300" role="status" aria-live="polite">
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="flex items-center justify-center w-16 h-16 rounded-xl bg-white dark:bg-neutral-900 border-2 border-neutral-300 dark:border-neutral-700 shadow-sm mb-4">
            <Shield size={32} className="text-neutral-400 dark:text-neutral-500" aria-hidden="true" />
          </div>
          <h3 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100 mb-2">
            Awaiting Verification
          </h3>
          <p className="text-neutral-600 dark:text-neutral-400 max-w-md">
            Select a scenario and press <kbd className="px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-xs font-mono">VERIFY SELECTED SCENARIO</kbd> to begin.
          </p>
        </div>
      </div>
    );
  }

  if (state === 'VERIFYING') {
    return (
      <div className="w-full rounded-2xl border-2 border-sky-400 dark:border-sky-500 bg-sky-50 dark:bg-sky-950/20 p-8 transition-all duration-300" role="status" aria-live="polite">
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="flex items-center justify-center w-16 h-16 rounded-xl bg-white dark:bg-neutral-900 border-2 border-sky-400 dark:border-sky-500 shadow-sm mb-4">
            <Loader2 size={32} className="text-sky-600 dark:text-sky-400 animate-spin" aria-hidden="true" />
          </div>
          <h3 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100 mb-2">
            Verifying with Backend
          </h3>
          <p className="text-sky-700 dark:text-sky-300 font-medium animate-pulse">
            Cryptographic verification in progress...
          </p>
        </div>
      </div>
    );
  }

  if (state === 'ERROR') {
    return (
      <div className="w-full rounded-2xl border-2 border-red-400 dark:border-red-500 bg-red-50 dark:bg-red-950/20 p-8 transition-all duration-300" role="alert" aria-live="assertive">
        <div className="flex items-center gap-4">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-white dark:bg-neutral-900 border-2 border-red-400 dark:border-red-500 shadow-sm flex-shrink-0">
            <AlertCircle size={28} className="text-red-600 dark:text-red-400" aria-hidden="true" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-red-700 dark:text-red-300 mb-2">
              Verification Error
            </h3>
            <p className="text-red-600 dark:text-red-400 text-sm">
              {error?.message || 'Unknown error occurred during verification'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  // COMPLETED state - render actual backend verdict
  if (!response) {
    return null;
  }

  const verdict = response.verdict;
  const isVerified = verdict === 'VERIFIED';
  const isContradicts = verdict === 'CONTRADICTS_POLICY';
  const isUnverifiable = verdict === 'UNVERIFIABLE';

  // Verdict-specific visual config
  const verdictConfig = isVerified
    ? {
        borderColor: 'border-emerald-400 dark:border-emerald-500',
        bgColor: 'bg-emerald-50 dark:bg-emerald-950/20',
        iconBgColor: 'bg-emerald-100 dark:bg-emerald-900/30 border-emerald-400 dark:border-emerald-500',
        iconColor: 'text-emerald-600 dark:text-emerald-400',
        badgeColor: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border-emerald-400 dark:border-emerald-500',
        titleColor: 'text-emerald-700 dark:text-emerald-300',
        authorityLabel: 'CRYPTOGRAPHICALLY VERIFIED',
        authorityIcon: ShieldCheck,
      }
    : isContradicts
    ? {
        borderColor: 'border-amber-400 dark:border-amber-500',
        bgColor: 'bg-amber-50 dark:bg-amber-950/20',
        iconBgColor: 'bg-amber-100 dark:bg-amber-900/30 border-amber-400 dark:border-amber-500',
        iconColor: 'text-amber-600 dark:text-amber-400',
        badgeColor: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-400 dark:border-amber-500',
        titleColor: 'text-amber-700 dark:text-amber-300',
        authorityLabel: 'CONTRADICTS POLICY',
        authorityIcon: Gavel,
      }
    : {
        borderColor: 'border-neutral-400 dark:border-neutral-600',
        bgColor: 'bg-neutral-50 dark:bg-neutral-900/50',
        iconBgColor: 'bg-neutral-100 dark:bg-neutral-800 border-neutral-400 dark:border-neutral-600',
        iconColor: 'text-neutral-600 dark:text-neutral-400',
        badgeColor: 'bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border-neutral-400 dark:border-neutral-600',
        titleColor: 'text-neutral-700 dark:text-neutral-300',
        authorityLabel: 'UNVERIFIABLE',
        authorityIcon: HelpCircle,
      };

  const AuthorityIcon = verdictConfig.authorityIcon;

  return (
    <div className={`w-full rounded-2xl border-2 ${verdictConfig.borderColor} ${verdictConfig.bgColor} p-6 transition-all duration-300`} role="status" aria-live="polite">
      {/* Header: Verdict + Authority Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div className={`flex items-center justify-center w-12 h-12 rounded-xl ${verdictConfig.iconBgColor} shadow-sm flex-shrink-0`}>
            <AuthorityIcon size={28} className={verdictConfig.iconColor} aria-hidden="true" />
          </div>
          <div>
            <span className={`text-sm font-semibold px-3 py-1 rounded-full border ${verdictConfig.badgeColor}`}>
              {verdict}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-current/50 bg-white/50 dark:bg-neutral-900/50 text-xs font-semibold tracking-wider" style={{ color: verdictConfig.iconColor }}>
            <verdictConfig.authorityIcon size={14} aria-hidden="true" />
            {verdictConfig.authorityLabel}
          </div>
          {response && (
            <Button
              variant="outline"
              size="sm"
              onClick={onOpenEvidence}
              className="gap-1.5 px-3 py-1.5 text-xs font-medium"
              aria-label="View detailed verification evidence"
            >
              <Shield size={12} />
              Evidence
            </Button>
          )}
        </div>
      </div>

      {/* Explanation from backend */}
      <div className="mb-6 p-4 rounded-lg bg-white dark:bg-neutral-900 border border-current/30">
        <p className={`font-medium ${verdictConfig.titleColor}`}>{response.explanation}</p>
      </div>

      {/* Verdict-specific details */}
      {isVerified && (
        <div className="space-y-4 mb-6">
          {/* Verified Fields */}
          {response.cryptographic_evidence.verified_fields.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-3 flex items-center gap-2">
                <Key size={14} aria-hidden="true" />
                Verified Fields
              </h4>
              <div className="flex flex-wrap gap-2">
                {response.cryptographic_evidence.verified_fields.map((field, idx) => (
                  <span key={idx} className="px-3 py-1.5 rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-sm font-mono border border-emerald-300 dark:border-emerald-700">
                    {field}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Signed Values */}
          {Object.keys(response.cryptographic_evidence.signed_values).length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-3 flex items-center gap-2">
                <Hash size={14} aria-hidden="true" />
                Signed Values
              </h4>
              <div className="space-y-2">
                {Object.entries(response.cryptographic_evidence.signed_values).map(([key, value]) => (
                  <div key={key} className="flex items-center gap-3 p-3 rounded-lg bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700">
                    <span className="text-xs font-medium text-neutral-500 dark:text-neutral-400 font-mono min-w-[120px]">{key}</span>
                    <span className="flex-1 text-sm font-mono text-neutral-900 dark:text-neutral-100 break-all">{value}</span>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(value)}
                      className="p-1.5 rounded hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
                      aria-label={`Copy ${key}`}
                    >
                      <Copy size={14} className="text-neutral-500 dark:text-neutral-400" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Empty state when no verified fields or signed values */}
          {response.cryptographic_evidence.verified_fields.length === 0 && Object.keys(response.cryptographic_evidence.signed_values).length === 0 && (
            <div className="text-center py-4 text-neutral-500 dark:text-neutral-400 text-sm">
              No cryptographic evidence fields returned by backend.
            </div>
          )}
        </div>
      )}

      {isContradicts && (
        <div className="space-y-4 mb-6">
          {/* Policy Result */}
          {response.policy.evaluated && (
            <div className="p-4 rounded-lg bg-white dark:bg-neutral-900 border border-amber-300 dark:border-amber-700">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-300 mb-3 flex items-center gap-2">
                <Gavel size={14} aria-hidden="true" />
                Policy Evaluation
              </h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-neutral-600 dark:text-neutral-400">Result</span>
                  <span className="font-semibold text-amber-700 dark:text-amber-300">{response.policy.result}</span>
                </div>
                {response.policy.error_code && (
                  <div className="flex items-center justify-between">
                    <span className="text-neutral-600 dark:text-neutral-400">Error Code</span>
                    <span className="font-mono text-amber-600 dark:text-amber-400">{response.policy.error_code}</span>
                  </div>
                )}
              </div>
            </div>
          )}
          <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800">
            <p className="text-sm text-amber-700 dark:text-amber-300">
              The cryptographic signature is valid, but the AI-extracted action conflicts with deterministic policy.
              This is a <span className="font-semibold">policy contradiction</span>, not a cryptographic failure.
            </p>
          </div>
        </div>
      )}

      {isUnverifiable && (
        <div className="space-y-4 mb-6">
          {/* Error Code from backend */}
          {response.error_code && (
            <div className="p-4 rounded-lg bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-3 flex items-center gap-2">
                <AlertCircle size={14} aria-hidden="true" />
                Backend Error Code
              </h4>
              <span className="font-mono text-neutral-700 dark:text-neutral-300">{response.error_code}</span>
            </div>
          )}
          <div className="p-4 rounded-lg bg-neutral-50 dark:bg-neutral-900/50 border border-neutral-200 dark:border-neutral-700">
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Sufficient cryptographic evidence was not established. The request could not be verified.
              {response.error_code && ` Reason: ${response.error_code.replace(/_/g, ' ').toLowerCase()}.`}
            </p>
          </div>
        </div>
      )}

{/* Request Metadata - Secondary Technical Area */}
      <div className="pt-4 border-t border-current/20">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
            <span className="font-medium">Request ID:</span>
            <span className="font-mono text-neutral-700 dark:text-neutral-300 select-all">{response.request_id}</span>
          </div>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(response.request_id)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neutral-100 dark:bg-neutral-800 hover:bg-neutral-200 dark:hover:bg-neutral-700 text-xs font-medium text-neutral-700 dark:text-neutral-300 transition-colors"
            aria-label="Copy Request ID"
          >
            <Copy size={14} aria-hidden="true" />
            Copy
          </button>
        </div>
      </div>
    </div>
  );
}

function ScenarioSelector({ selectedScenario, onSelect, onVerify, onReset, isVerifying, verificationState, response, error, onOpenEvidence }: {
  selectedScenario: FixtureId | null;
  onSelect: (id: FixtureId) => void;
  onVerify: () => void;
  onReset: () => void;
  isVerifying: boolean;
  verificationState: VerificationState;
  response: VerifyResponse | null;
  error: Error | null;
  onOpenEvidence: () => void;
}) {
  return (
    <section className="py-16 px-4" aria-labelledby="scenario-heading">
      <div className="max-w-4xl mx-auto">
        <header className="text-center mb-10">
          <h2 id="scenario-heading" className="text-2xl lg:text-3xl font-semibold text-neutral-900 dark:text-neutral-50 mb-4">
            Select a Verification Scenario
          </h2>
          <p className="text-lg text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
            Each scenario exercises a different path through the verification pipeline.
            The backend response is the only source of truth.
          </p>
        </header>

        <div className="space-y-4 mb-8" role="radiogroup" aria-label="Verification scenarios">
          {scenarios.map((scenario) => (
            <ScenarioCard
              key={scenario.id}
              scenario={scenario}
              isSelected={selectedScenario === scenario.id}
              onSelect={() => onSelect(scenario.id)}
            />
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full">
          <Button
            size="lg"
            className="gap-2 px-8 py-3.5 text-base font-medium min-w-[200px] w-full sm:w-auto"
            onClick={onVerify}
            disabled={!selectedScenario || isVerifying}
            aria-disabled={!selectedScenario || isVerifying}
          >
            {isVerifying && <Loader2 size={20} className="animate-spin" />}
            {isVerifying ? 'VERIFYING...' : 'VERIFY SELECTED SCENARIO'}
          </Button>
          {selectedScenario && verificationState !== 'IDLE' && (
            <Button
              variant="outline"
              size="lg"
              className="gap-2 px-6 py-3.5 text-base font-medium w-full sm:w-auto"
              onClick={onReset}
              disabled={isVerifying}
            >
              <ChevronUp size={20} />
              RESET
            </Button>
          )}
        </div>

{verificationState !== 'IDLE' && (
            <div className="mt-8 animate-in fade-in slide-in-from-top-2 duration-300">
              <VerdictPanel
                state={verificationState}
                response={response}
                error={error}
                onOpenEvidence={onOpenEvidence}
              />
            </div>
          )}
      </div>
    </section>
  );
}

export default function App() {
  const [selectedScenario, setSelectedScenario] = useState<FixtureId | null>(null);
  const [verificationState, setVerificationState] = useState<VerificationState>('IDLE');
  const [response, setResponse] = useState<VerifyResponse | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [evidenceDrawerOpen, setEvidenceDrawerOpen] = useState(false);

  const handleSelect = (id: FixtureId) => {
    setSelectedScenario(id);
    setVerificationState('IDLE');
    setResponse(null);
    setError(null);
  };

  const handleVerify = async () => {
    if (!selectedScenario) return;

    setVerificationState('VERIFYING');
    setError(null);

    try {
      const result = await verifyFixture(selectedScenario);
      setResponse(result);
      setVerificationState('COMPLETED');
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Unknown error'));
      setVerificationState('ERROR');
    }
  };

  const handleReset = () => {
    setVerificationState('IDLE');
    setResponse(null);
    setError(null);
  };

  const handleOpenEvidence = () => {
    setEvidenceDrawerOpen(true);
  };

  return (
    <div className="min-h-screen bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-50 antialiased">
      <main className="flex flex-col">
        <Hero />
        <VerificationPipeline />
        <ScenarioSelector
          selectedScenario={selectedScenario}
          onSelect={handleSelect}
          onVerify={handleVerify}
          onReset={handleReset}
          isVerifying={verificationState === 'VERIFYING'}
          verificationState={verificationState}
          response={response}
          error={error}
          onOpenEvidence={handleOpenEvidence}
        />
        <SecurityLegend />
        {response && <EvidenceDrawer response={response} open={evidenceDrawerOpen} onClose={() => setEvidenceDrawerOpen(false)} />}
      </main>
    </div>
  );
}