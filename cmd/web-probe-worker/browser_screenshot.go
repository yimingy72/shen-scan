package main

import (
	"bytes"
	"errors"
	"image/png"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/httpx/runner"
	"scanplatform/internal/webevidence"
)

const screenshotEngine = "httpx-runner-v1.12.0/screenshot/system-chrome"
const screenshotWidth = 1280
const screenshotHeight = 720

func browserCaptureScreenshot(page *rod.Page) *webevidence.BrowserScreenshot {
	output := &webevidence.BrowserScreenshot{WebStage: webevidence.WebStage{State: "failed"}}
	// The caller sets a fixed device viewport. Capture only the first screen,
	// so long documents cannot expand the screenshot allocation.
	guard := func() error {
		metrics, err := (proto.PageGetLayoutMetrics{}).Call(page)
		if err != nil {
			return err
		}
		if metrics.CSSVisualViewport == nil || metrics.CSSVisualViewport.ClientWidth != screenshotWidth || metrics.CSSVisualViewport.ClientHeight != screenshotHeight {
			return errors.New("screenshot viewport differs from fixed1280x720")
		}
		size, err := page.Eval(`() => document.documentElement.outerHTML.length`)
		if err != nil {
			return err
		}
		if size.Value.Int() > webevidence.MaxBody {
			return errors.New("screenshot rendered HTML exceeds bounded SDK body limit")
		}
		return nil
	}
	data, _, err := runner.ScreenshotWithBodyFromPage(page, time.Second, false, guard)
	if err != nil {
		output.Error = err.Error()
		output.StopReason = "httpx-screenshot-error"
		return output
	}
	if len(data) > webevidence.MaxScreenshot {
		output.State = "partial"
		output.Error = "screenshot PNG exceeds byte limit"
		output.StopReason = "screenshot-byte-limit"
		return output
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width != screenshotWidth || config.Height != screenshotHeight {
		output.State = "partial"
		output.Error = "invalid or oversized screenshot PNG"
		output.StopReason = "screenshot-dimension-limit"
		return output
	}
	output.State = "complete"
	output.PNG = data
	output.Width = config.Width
	output.Height = config.Height
	output.SHA256 = webevidence.SHA256(data)
	return output
}
