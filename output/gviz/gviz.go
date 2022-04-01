package gviz

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/beta/freetype/truetype"
	"github.com/goccy/go-graphviz"
	"github.com/k1LoW/ffff"
	"github.com/k1LoW/tbls/config"
	"github.com/k1LoW/tbls/output/dot"
	"github.com/k1LoW/tbls/schema"
	"github.com/pkg/errors"
	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"
)

// Gviz struct
type Gviz struct {
	config *config.Config
	dot    *dot.Dot
}

// New return Gviz
func New(c *config.Config) *Gviz {
	return &Gviz{
		config: c,
		dot:    dot.New(c),
	}
}

// OutputSchema output dot format for full relation.
func (g *Gviz) OutputSchema(wr io.Writer, s *schema.Schema) error {
	unflattenTool, err := exec.LookPath("unflatten")
	var dot []byte
	if err != nil {
		buf := &bytes.Buffer{}
		if err := g.dot.OutputSchema(buf, s); err != nil {
			return errors.WithStack(err)
		}
		dot = buf.Bytes()
	} else {
		file, err := os.OpenFile("temp.dot", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return errors.WithStack(err)
		}
		defer func() {
			err := file.Close()
			if err != nil {
				os.Exit(1)
			}
		}()
		if err := g.dot.OutputSchema(file, s); err != nil {
			return errors.WithStack(err)
		}

		cmdUnflattenAttr := &exec.Cmd{
			Path:   unflattenTool,
			Args:   []string{unflattenTool, "-l", "50", "-c", "50", "-o", "unflatten.dot", "temp.dot"},
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		}

		if err := cmdUnflattenAttr.Run(); err != nil {
			return errors.WithStack(err)
		}

		updatedFile, err := os.Open("unflatten.dot")
		if err != nil {
			return errors.WithStack(err)
		}
		defer func() {
			err := updatedFile.Close()
			if err != nil {
				os.Exit(1)
			}
		}()

		fileinfo, err := updatedFile.Stat()
		if err != nil {
			return errors.WithStack(err)
		}

		filesize := fileinfo.Size()
		dot = make([]byte, filesize)

		_, err = updatedFile.Read(dot)
		if err != nil {
			return errors.WithStack(err)
		}
		err = os.Remove("temp.dot")
		if err != nil {
			return errors.WithStack(err)
		}
		err = os.Remove("unflatten.dot")
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return g.render(wr, dot)
}

// OutputTable output dot format for table.
func (g *Gviz) OutputTable(wr io.Writer, t *schema.Table) error {
	buf := &bytes.Buffer{}
	err := g.dot.OutputTable(buf, t)
	if err != nil {
		return errors.WithStack(err)
	}
	return g.render(wr, buf.Bytes())
}

func (g *Gviz) render(wr io.Writer, b []byte) (e error) {
	gviz := graphviz.New()
	if g.config.ER.Font != "" {
		faceFunc, err := getFaceFunc(g.config.ER.Font)
		if err != nil {
			return errors.WithStack(err)
		}
		gviz.SetFontFace(faceFunc)
	}
	graph, err := graphviz.ParseBytes(b)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if err := gviz.Close(); err != nil {
			e = errors.WithStack(err)
		}
		if err := graph.Close(); err != nil {
			e = errors.WithStack(err)
		}
	}()
	if err := gviz.Render(graph, graphviz.Format(g.config.ER.Format), wr); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// getFaceFunc
func getFaceFunc(keyword string) (func(size float64) (font.Face, error), error) {
	var (
		faceFunc func(size float64) (font.Face, error)
		path     string
	)

	fi, err := os.Stat(keyword)
	if err == nil && !fi.IsDir() {
		path = keyword
	} else {
		path, err = ffff.FuzzyFindPath(keyword)
		if err != nil {
			return faceFunc, errors.WithStack(err)
		}
	}

	fb, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return faceFunc, errors.WithStack(err)
	}

	if strings.HasSuffix(path, ".otf") {
		// OpenType
		ft, err := sfnt.Parse(fb)
		if err != nil {
			return faceFunc, errors.WithStack(err)
		}
		faceFunc = func(size float64) (font.Face, error) {
			opt := &opentype.FaceOptions{
				Size:    size,
				DPI:     0,
				Hinting: 0,
			}
			return opentype.NewFace(ft, opt)
		}
	} else {
		// TrueType
		ft, err := truetype.Parse(fb)
		if err != nil {
			return faceFunc, errors.WithStack(err)
		}
		faceFunc = func(size float64) (font.Face, error) {
			opt := &truetype.Options{
				Size:              size,
				DPI:               0,
				Hinting:           0,
				GlyphCacheEntries: 0,
				SubPixelsX:        0,
				SubPixelsY:        0,
			}
			return truetype.NewFace(ft, opt), nil
		}
	}
	return faceFunc, nil
}
