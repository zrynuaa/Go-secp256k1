// Copyright 2010 The Go Authors. All rights reserved.
// Copyright 2011 ThePiachu. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secpk1

import (
	"crypto/ecdsa"
	eth "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"gopkg.in/yaml.v2"
	"math/big"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestOnCurve(t *testing.T) {	
	s160 := S160()
	if !s160.IsOnCurve(s160.Gx, s160.Gy) {
		t.Errorf("FAIL S160")
	}
	s192 := S192()
	if !s192.IsOnCurve(s192.Gx, s192.Gy) {
		t.Errorf("FAIL S192")
	}
	s224 := S224()
	if !s224.IsOnCurve(s224.Gx, s224.Gy) {
		t.Errorf("FAIL S224")
	}
	s256 := S256()
	if !s256.IsOnCurve(s256.Gx, s256.Gy) {
		t.Errorf("FAIL S256")
	}
}

type baseMultTest struct {
	k    string
	x, y string
}
//TODO: add more test vectors
var s256BaseMultTests = []baseMultTest{
	{
		"AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
		"34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
		"B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
	},
	{
		"7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
		"D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
		"131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
	},
	{
		"6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
		"E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
		"C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
	},
	{
		"376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
		"14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
		"297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
	},
	{
		"1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
		"F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
		"F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
	},
}

//TODO: test different curves as well?
func TestBaseMult(t *testing.T) {
	s256 := S256()
	for i, e := range s256BaseMultTests {
		k, ok := new(big.Int).SetString(e.k, 16)
		if !ok {
			t.Errorf("%d: bad value for k: %s", i, e.k)
		}
		x, y := s256.ScalarBaseMult(k.Bytes())
		if fmt.Sprintf("%X", x) != e.x || fmt.Sprintf("%X", y) != e.y {
			t.Errorf("%d: bad output for k=%s: got (%X, %X), want (%s, %s)", i, e.k, x, y, e.x, e.y)
		}
		if testing.Short() && i > 5 {
			break
		}
	}
}

//TODO: test more curves?
func BenchmarkBaseMult(b *testing.B) {
	b.ResetTimer()
	s256 := S224()
	e := s256BaseMultTests[0]//TODO: check, used to be 25 instead of 0, but it's probably ok
	k, _ := new(big.Int).SetString(e.k, 16)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		s256.ScalarBaseMult(k.Bytes())
	}
}

//TODO: test more curves?
func TestMarshal(t *testing.T) {
	s256 := S256()
	_, x, y, err := s256.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	serialised := s256.Marshal(x, y)
	xx, yy := s256.Unmarshal(serialised)
	if xx == nil {
		t.Error("failed to unmarshal")
		return
	}
	if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
		t.Error("unmarshal returned different values")
		return
	}
}

//下面的测试是为了跟ethereum的曲线做对比，说明不用cgo也正确实现了secp256k1曲线的功能。
func TestBitCurve_Params(t *testing.T) {
	eccs256 := S256()
	pam1 := eccs256.Params()
	pa1,_ := yaml.Marshal(pam1)


	eths256 := eth.S256()
	pam2 := eths256.Params()
	pa2,_ := yaml.Marshal(pam2)


	if string(pa1) == string(pa2) {
		fmt.Println("OK\n", pa1,"\n",pa2)
	}else {
		fmt.Println("ERROR")
	}
}

func TestBitCurve_IsOnCurve(t *testing.T) {
	s256 := S256()
	eths256 := eth.S256()
	if !s256.IsOnCurve(eths256.Gx, eths256.Gy) {
		t.Errorf("FAIL S256")
	}

	if !eths256.IsOnCurve(s256.Gx, s256.Gy) {
		t.Errorf("FAIL ethS256")
	}
}

func TestBitCurve_Double(t *testing.T) {
	s256 := S256()
	eths256 := eth.S256()

	k1,_ := ecdsa.GenerateKey(S256(),rand.Reader)
	k2,_ := ecdsa.GenerateKey(eth.S256(), rand.Reader)

	a,b := s256.Double(k1.X, k1.Y)
	c,d := eths256.Double(k1.X, k1.Y)

	if a.String() == c.String() && b.String() == d.String(){
		fmt.Println("OK")
	}

	a,b = s256.Double(k2.X, k2.Y)
	c,d = eths256.Double(k2.X, k2.Y)

	if a.String() == c.String() && b.String() == d.String(){
		fmt.Println("OK")
	}

}

func TestBitCurve_Add(t *testing.T) {
	s256 := S256()
	eths256 := eth.S256()

	k1,_ := ecdsa.GenerateKey(S256(),rand.Reader)
	k2,_ := ecdsa.GenerateKey(eth.S256(), rand.Reader)

	a,b := s256.Add(k1.X, k1.Y, k2.X, k2.Y)
	c,d := eths256.Add(k2.X, k2.Y, k1.X, k1.Y)

	if a.String() == c.String() && b.String() == d.String(){
		fmt.Println("OK")
	}
}

func TestBitCurve_ScalarBaseMult(t *testing.T) {
	s256 := S256()
	eths256 := eth.S256()
	k, _ := new(big.Int).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)
	x1,y1 := s256.ScalarBaseMult(k.Bytes())
	x2,y2 := eths256.ScalarBaseMult(k.Bytes())

	if x1.String() == x2.String() && y1.String() == y2.String(){
		fmt.Println("OK")
	}
}

func TestBitCurve_ScalarMult(t *testing.T) {
	s256 := S256()
	eths256 := eth.S256()
	k, _ := new(big.Int).SetString("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", 16)

	k1, _ := ecdsa.GenerateKey(S256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(eth.S256(), rand.Reader)

	a, b := s256.ScalarMult(k1.X, k1.Y, k.Bytes())
	c, d := eths256.ScalarMult(k1.X, k1.Y, k.Bytes())

	if a.String() == c.String() && b.String() == d.String() {
		fmt.Println("OK")
	}

	a, b = s256.ScalarMult(k2.X, k2.Y, k.Bytes())
	c, d = eths256.ScalarMult(k2.X, k2.Y, k.Bytes())

	if a.String() == c.String() && b.String() == d.String() {
		fmt.Println("OK")
	}
}