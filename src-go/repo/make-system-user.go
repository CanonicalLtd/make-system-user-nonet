/*
* Copyright (C) 2017 Canonical Ltd
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 3 as
* published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*  Authored by: Kyle Nitzsche <kyle.nitzsche@canonical.com>
*
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/signtool"
)

type signSuite struct {
	keypairMgr asserts.KeypairManager
	testKeyID  string
}

func times() (string, string) {
	now := time.Now()
	since := now.AddDate(0, 0, -2)
	until := now.AddDate(1, 0, 0)

	s := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.UTC)
	sStr := fmt.Sprintf("%q", s.Format(time.RFC3339))
	sStr = sStr[1:len(sStr)-2] + "-00:00"

	u := time.Date(until.Year(), until.Month(), until.Day(), 0, 0, 0, 0, time.UTC)
	uStr := fmt.Sprintf("%q", u.Format(time.RFC3339))
	uStr = uStr[1:len(uStr)-2] + "-00:00"

	return sStr, uStr
}

func systemUserJson(opts *options) []byte {
	since, until := times()
	m := map[string]interface{}{
		"type":         "system-user",
		"authority-id": opts.authorityId,
		"brand-id":     opts.brand,
		"series":       []interface{}{"16"},
		"models":       []interface{}{opts.model},
		"name":         opts.user + "User",
		"username":     opts.user,
		"email":        opts.user + "@localhost",
		"password":     opts.passwordHash,
		"since":        since,
		"until":        until,
		"revision":     "1",
	}
	//"since":        "2017-01-01T00:00:00-00:00",
	b, _ := json.Marshal(m)
	return b
}

type options struct {
	key           string
	authorityId   string
	gpgDir        string
	user          string
	password      string
	passwordHash  string
	model         string
	brand         string
	signedAsserts string
	err           string
}

var verbose bool

func args() *options {
	opts := &options{}
	flag.StringVar(&opts.key, "key", "", "The key name ('uid') to sign with")
	flag.StringVar(&opts.authorityId, "authority-id", "", "The Ubuntu SSO account ID asociated with the signing key")
	flag.StringVar(&opts.gpgDir, "gpg-dir", "", "The path to the directory that contains the GPG signing key files")
	flag.StringVar(&opts.user, "user", "", "The user to be created")
	flag.StringVar(&opts.password, "password", "", "The password for the user to be created")
	flag.StringVar(&opts.model, "model", "", "The model on which the user is to be created")
	flag.StringVar(&opts.brand, "brand", "", "The brand on which the user is to be created")
	//TODO fix
	flag.StringVar(&opts.signedAsserts, "signed-asserts", "", "The file containing the signed account and account-key asserts, where they match all other run time values")
	flag.BoolVar(&verbose, "verbose", false, "Display verbose output")
	flag.Parse()
	if len(opts.key) == 0 {
		opts.err = "Error: please use '-key KEY'"
	}
	return opts
}

func hash(opts *options) bool {
	cmdArgs := []string{opts.password}
	snapPath := os.Getenv("SNAP")
	path := snapPath + "/bin/gen-hash.py"
	hash, herr := exec.Command(path, cmdArgs...).Output()
	if herr != nil {
		fmt.Printf("Error: hash failed. %q\n", herr)
		return false
	}
	opts.passwordHash = string(hash)[:len(hash)-1] //remove trailing newline from hash
	return true
}

func main() {
	opts := args()
	if len(opts.err) > 0 {
		fmt.Printf("%q. Stopping.\n", opts.err)
		return
	}

	if verbose {
		fmt.Printf("key: %q\n", opts.key)
		fmt.Printf("authority-id: %q\n", opts.authorityId)
		fmt.Printf("gpgDir: %q\n", opts.gpgDir)
		fmt.Printf("user: %q\n", opts.user)
		fmt.Printf("password: %q\n", opts.password)
		fmt.Printf("model: %q\n", opts.model)
		fmt.Printf("brand: %q\n", opts.brand)
		fmt.Printf("verbose: %q\n", verbose)
		fmt.Printf("\nSystem User assertion JSON:\n%q\n", systemUserJson(opts))
	}

	// allow user to point to non-standard dir for gpg signing key
	if len(opts.gpgDir) > 0 {
		os.Setenv("SNAP_GNUPG_HOME", opts.gpgDir)
	}

	// get password hash, currently from ./gen-has.py
	if !hash(opts) {
		return
	}

	keypairMgr := asserts.NewGPGKeypairManager()

	// set up to use the specified key
	privKey, err := keypairMgr.GetByName(opts.key)
	if err != nil {
		fmt.Printf("Error: cannot find key: %v\n", err)
		return
	}
	signOpts := signtool.Options{
		KeyID:     privKey.PublicKey().ID(),
		Statement: systemUserJson(opts),
	}

	//sign the system user assertion
	encodedAssert, err := signtool.Sign(&signOpts, keypairMgr)
	if err != nil {
		fmt.Printf("Error: cannot sign the asserttion. %q\n", err)
		return
	}

	//get the canned signed assertions. Note they MUST provide the signed account and
	//account-key asserts for the key used here to sign the system-user-assertion
	//TODO canned asserts to be packaged in snap
	cannedAsserts, err := ioutil.ReadFile(opts.signedAsserts)
	if err != nil {
		fmt.Printf("Error: cannot read canned asserttion file. %q\n", err)
		return
	}

	// concatenate
	autoImport := append(cannedAsserts[:], encodedAssert[:]...)

	if verbose {
		_, _ = os.Stdout.Write(autoImport)
	}

	output := "auto-import.assert"
	//check if file exists
	if _, err := os.Stat(output); err == nil {
		fmt.Printf("Warning: output file (%q) exists already, it will be deleted and recreated\n", output)
		e := os.Remove(output)
		if e != nil {
			fmt.Printf("Error: file (%q) could not be deleted. Please delete it manually and then run this program again", output)
			return
		}
	}
	//write to local file
	errF := ioutil.WriteFile("auto-import.assert", autoImport, 0644)
	if errF != nil {
		fmt.Printf("Error: Cannot write final file %q", errF)
		return
	}

	return
}
