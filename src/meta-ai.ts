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
