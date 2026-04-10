-- User feedback for ML retraining
CREATE TABLE IF NOT EXISTS public.feedback_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN ('false_positive', 'false_negative')),
    score_at_report INT,
    comment TEXT,
    reviewed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_feedback_domain ON public.feedback_reports(domain);
CREATE INDEX idx_feedback_type ON public.feedback_reports(report_type);
CREATE INDEX idx_feedback_reviewed ON public.feedback_reports(reviewed) WHERE NOT reviewed;

ALTER TABLE public.feedback_reports ENABLE ROW LEVEL SECURITY;

-- Users can insert their own reports
CREATE POLICY feedback_insert ON public.feedback_reports
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Users can read their own reports
CREATE POLICY feedback_read ON public.feedback_reports
    FOR SELECT USING (auth.uid() = user_id);
