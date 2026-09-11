import { callService } from './clients';

export type ConverseMode = 'forensic' | 'consumer';
export type ResponseMode = 'plain' | 'technical';

export interface ConversationTurn {
  role: 'user' | 'assistant';
  content: string;
}

export interface MetaAISource {
  type: string;
  id: string;
  timestamp?: string | null;
}

export interface MetaAIRequest {
  requestId: string;
  mode: ConverseMode;
  query: string;
  context: Record<string, unknown>;
  conversationHistory?: ConversationTurn[];
  responseMode?: ResponseMode;
  language?: string;
}

export interface MetaAIResponse {
  response: string;
  sources: MetaAISource[];
  confidence: number | null;
  model: string | null;
  modelProvider: string | null;
  aiGenerated: boolean;
}

type ConverseUpstream = {
  status?: string;
  response?: string;
  sources?: MetaAISource[];
  confidence?: number | null;
  model?: string;
  model_provider?: string;
};

const FALLBACK_RESPONSE: Record<ConverseMode, string> = {
  consumer:
    "I'm having trouble connecting right now, but your report has already been sent to security. Stay where it's safe.",
  forensic: 'The AI assistant is temporarily unavailable. Please try your question again in a moment.'
};

// Conversational AI (forensic Q&A, consumer voice guidance) is proxied through
// masterai's /ai/converse rather than calling a model provider directly from
// here. masterai already owns the Groq/Llama client, model selection, and the
// model_provider transparency field the rest of this system relies on to tell
// a real AI answer from a heuristic fallback — duplicating that in a second
// integration would mean a second provider key and a second place to keep honest.
export async function queryMetaAI(req: MetaAIRequest): Promise<MetaAIResponse> {
  const result = await callService<ConverseUpstream>({
    service: 'mainAgent',
    path: '/ai/converse',
    // callService's own default is 3s if this isn't set — nowhere near enough for a
    // real completion, let alone a Render free-tier cold start. Every other AI call
    // in orchestrator.ts already uses 12s+ for exactly this reason; this one didn't,
    // which alone was enough to make conversational AI look broken.
    timeoutMs: 20000,
    body: {
      request_id: req.requestId,
      mode: req.mode,
      query: req.query,
      context: req.context,
      conversation_history: req.conversationHistory || [],
      response_mode: req.responseMode || 'plain',
      language: req.language || 'en'
    }
  });

  const data = result.data;
  const hasRealResponse =
    result.ok && !result.fallback && typeof data?.response === 'string' && data.response.length > 0;

  if (!hasRealResponse) {
    return {
      response: FALLBACK_RESPONSE[req.mode],
      sources: [],
      confidence: null,
      model: null,
      modelProvider: null,
      aiGenerated: false
    };
  }

  return {
    response: data.response as string,
    sources: data.sources || [],
    confidence: typeof data.confidence === 'number' ? data.confidence : null,
    model: data.model || null,
    modelProvider: data.model_provider || null,
    aiGenerated: data.model_provider !== 'heuristic-fallback'
  };
}

export interface EmergencyIntakeRequest {
  requestId: string;
  transcript: string;
  conversationHistory?: ConversationTurn[];
  currentDescription: string;
  language?: string;
}

export interface EmergencyIntakeResponse {
  spokenResponse: string;
  rewrittenDescription: string;
  followUpQuestion: string | null;
  dangerDetected: boolean;
  incidentTypeGuess: string | null;
  aiGenerated: boolean;
}

type EmergencyIntakeUpstream = {
  status?: string;
  spoken_response?: string;
  rewritten_description?: string;
  follow_up_question?: string | null;
  danger_detected?: boolean;
  incident_type_guess?: string | null;
  model_provider?: string;
};

// Dedicated endpoint (not /ai/converse) because this needs a different, structured
// contract — a rewritten description, at most one follow-up question, and a danger
// flag the frontend uses to switch the guest from speaking to typing — not a free-text
// chat reply.
export async function queryEmergencyIntake(req: EmergencyIntakeRequest): Promise<EmergencyIntakeResponse> {
  const result = await callService<EmergencyIntakeUpstream>({
    service: 'mainAgent',
    path: '/ai/emergency-intake',
    timeoutMs: 20000,
    body: {
      request_id: req.requestId,
      transcript: req.transcript,
      conversation_history: req.conversationHistory || [],
      current_description: req.currentDescription,
      language: req.language || 'en'
    }
  });

  const data = result.data;
  const hasRealResponse = result.ok && !result.fallback && typeof data?.rewritten_description === 'string';

  if (!hasRealResponse) {
    return {
      spokenResponse: 'Help is on the way. Please stay safe.',
      rewrittenDescription: `${req.currentDescription} ${req.transcript}`.trim(),
      followUpQuestion: null,
      dangerDetected: false,
      incidentTypeGuess: null,
      aiGenerated: false
    };
  }

  return {
    spokenResponse: data.spoken_response || 'Help is on the way.',
    rewrittenDescription: data.rewritten_description as string,
    followUpQuestion: data.follow_up_question || null,
    dangerDetected: Boolean(data.danger_detected),
    incidentTypeGuess: data.incident_type_guess || null,
    aiGenerated: data.model_provider !== 'heuristic-fallback'
  };
}
