package ehole

import (
	"bytes"
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils/httputils"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"strings"
)

const (
	KeywordMethod = "keyword"
	RegularMethod = "regular"
	FaviconMethod = "faviconhash"
)

const (
	BodyLocation   = "body"
	HeaderLocation = "header"
	TitleLocation  = "title"
)

func NewEHoleEngine(data []byte) (*EHoleEngine, error) {
	var engine *EHoleEngine
	err := resources.UnmarshalData(data, &engine)
	if err != nil {
		return nil, err
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type EHoleEngine struct {
	LegacyTitleBody bool           `json:"-"`
	Fingerprints    []*Fingerprint `json:"fingerprint"`
	FaviconMap      map[string]string
	// MatchDetailEnabled records on each hit the keyword or text it matched.
	MatchDetailEnabled bool `json:"-"`
}

func (engine *EHoleEngine) Name() string {
	return "ehole"
}

func (engine *EHoleEngine) Len() int {
	return len(engine.Fingerprints)
}

func (engine *EHoleEngine) Compile() error {
	engine.FaviconMap = make(map[string]string)
	for _, finger := range engine.Fingerprints {
		if finger.Method == RegularMethod {
			finger.compiledRegexp = make([]*regexp.Regexp, len(finger.Keyword))
			for i, reg := range finger.Keyword {
				/** Fix bug
				 * 使用 append 会导致数组前面有 len(finger.Keyword) 个 nil，在 `reg.Match` 时导致 panic（144行）
				 * 匹配引擎会将内容全部转小写，正则表达式也需要转小写
				 */
				//finger.compiledRegexp = append(finger.compiledRegexp, regexp.MustCompile(reg))
				compiled, err := regexp.Compile(strings.ToLower(reg))
				if err != nil {
					return fmt.Errorf("EHole %s: %w", finger.Cms, err)
				}
				finger.compiledRegexp[i] = compiled
			}
		} else if finger.Method == KeywordMethod {
			finger.LowerKeyword = make([]string, len(finger.Keyword))
			for i, word := range finger.Keyword {
				//finger.lowerKeyword = append(finger.lowerKeyword, strings.ToLower(word))
				finger.LowerKeyword[i] = strings.ToLower(word)
			}
		} else if finger.Method == FaviconMethod {
			for _, hash := range finger.Keyword {
				engine.FaviconMap[hash] = finger.Cms
			}
		}
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *EHoleEngine) WebMatch(content []byte) common.Frameworks {
	var header, body string
	content = bytes.ToLower(content)
	bodyBytes, headerBytes, ok := httputils.SplitHttpRaw(content)
	if ok {
		header = string(headerBytes)
		body = string(bodyBytes)
		return engine.MatchWithHeaderAndBody(header, body)
	}
	return make(common.Frameworks)
}

// ServiceMatch 实现Service指纹匹配 - ehole不支持Service指纹
func (engine *EHoleEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// ehole不支持Service指纹识别
	return nil
}

func (engine *EHoleEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // ehole支持Web指纹
		SupportService: false, // ehole不支持Service指纹
	}
}

func (engine *EHoleEngine) MatchWithHeaderAndBody(header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.Fingerprints {
		candidate := finger
		if engine.LegacyTitleBody && finger.Location == TitleLocation {
			copyFinger := *finger
			copyFinger.Location = BodyLocation
			candidate = &copyFinger
		}
		frame := candidate.Match(header, body)
		if frame != nil {
			if !engine.MatchDetailEnabled {
				frame.MatchDetail = nil
			}
			frames.Add(frame)
		}
	}
	return frames
}

type Fingerprint struct {
	Cms            string   `json:"cms"`
	Method         string   `json:"method"`
	Location       string   `json:"location"`
	Keyword        []string `json:"keyword"`
	LowerKeyword   []string `json:"-"`
	compiledRegexp []*regexp.Regexp
}

func (finger *Fingerprint) Match(header, body string) *common.Framework {
	var content string
	switch finger.Location {
	case BodyLocation:
		content = body
	case TitleLocation:
		content = titleText(body)
	case HeaderLocation:
		content = header
	default:
		return nil
	}
	if !finger.MatchMethod(content) {
		return nil
	}
	frame := common.NewFramework(finger.Cms, common.FrameFromEhole)
	frame.MatchDetail = finger.matched(content)
	return frame
}

// matched is what a matching fingerprint found in content: its first keyword,
// or the text its first regexp matched.
func (finger *Fingerprint) matched(content string) *common.MatchDetail {
	switch {
	case finger.Method == KeywordMethod && len(finger.LowerKeyword) > 0:
		return &common.MatchDetail{MatcherType: "word", MatcherValue: finger.LowerKeyword[0]}
	case finger.Method == RegularMethod && len(finger.compiledRegexp) > 0:
		return &common.MatchDetail{MatcherType: "word", MatcherValue: finger.compiledRegexp[0].FindString(content)}
	}
	return nil
}

func (finger *Fingerprint) MatchMethod(content string) bool {
	switch finger.Method {
	case KeywordMethod:
		return finger.MatchKeyword(content)
	case RegularMethod:
		return finger.MatchRegexp(content)
	default:
		return false
	}
}

func (finger *Fingerprint) MatchKeyword(content string) bool {
	// Fix bug: 匹配引擎会将内容全部转小写，这里需要使用 LowerKeyword 检测
	//for _, k := range finger.Keyword {
	for _, k := range finger.LowerKeyword {
		if !strings.Contains(content, k) {
			return false
		}
	}
	return true
}

func (finger *Fingerprint) MatchRegexp(content string) bool {
	for _, reg := range finger.compiledRegexp {
		if !reg.Match([]byte(content)) {
			return false
		}
	}
	return true
}

// titleText returns text inside a real title element; body text cannot satisfy it.
func titleText(body string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	inside := false
	var text strings.Builder
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return text.String()
			}
			return ""
		case html.StartTagToken:
			t := z.Token()
			if t.Data == "title" {
				inside = true
			}
		case html.EndTagToken:
			t := z.Token()
			if inside && t.Data == "title" {
				return text.String()
			}
		case html.TextToken:
			if inside {
				text.Write(z.Text())
			}
		}
	}
}
