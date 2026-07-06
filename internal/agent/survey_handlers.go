package agent

// survey:read (plan 28 Phase 4) — the read-only "flight". The panel ships
// a declarative probe catalog as params; the agent runs it against the
// FIXED allowlist of read-only primitives in internal/survey (the panel is
// UNTRUSTED — see docs/AGENT_SURVEY_SPEC.md, Decision 2). The response is a
// synchronous command result (the poll transport drops streams), size and
// time bounded, and always partial-safe.

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/survey"
)

// surveyReadTimeout is the agent-side deadline. Comfortably under the
// panel's 60s (survey_service.SURVEY_TIMEOUT) so a slow glob degrades that
// probe, not the whole run.
const surveyReadTimeout = 45 * time.Second

type surveyReadParams struct {
	Catalog survey.Catalog `json:"catalog"`
}

func (a *Agent) handleSurveyRead(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Linux-only in v1 (the capability is only advertised there). Register
	// unconditionally so a stray call gets a clean error, not "unknown
	// action" — matching the systemd-family house pattern.
	if runtime.GOOS != "linux" {
		return nil, errors.New("survey:read is Linux-only")
	}

	var p surveyReadParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
	}

	cctx, cancel := context.WithTimeout(ctx, surveyReadTimeout)
	defer cancel()

	exec := survey.NewExecutor(survey.NewLiveProbes(a.dockerContainerLister()))
	return exec.Run(cctx, p.Catalog), nil
}

// dockerContainerLister adapts the agent's docker client to the survey
// package's DockerLister. Returns nil when docker is unavailable so the
// docker probe is simply reported absent.
func (a *Agent) dockerContainerLister() survey.DockerLister {
	if a.docker == nil {
		return nil
	}
	return func(ctx context.Context) []survey.Container {
		infos, err := a.docker.ListContainers(ctx, false) // running only
		if err != nil {
			return nil
		}
		out := make([]survey.Container, 0, len(infos))
		for _, c := range infos {
			var ports []string
			for _, pm := range c.Ports {
				if pm.PublicPort != 0 {
					ports = append(ports,
						strconv.Itoa(int(pm.PublicPort))+"->"+strconv.Itoa(int(pm.PrivatePort)))
				}
			}
			out = append(out, survey.Container{
				Name:  c.Name,
				Image: c.Image,
				Ports: ports,
			})
		}
		return out
	}
}
