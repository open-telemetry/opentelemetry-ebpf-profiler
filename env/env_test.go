package env

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetConfiguration(t *testing.T) {
	_, err := NewEnvironment("aws", "0xfeeddeadbeefbeef")
	require.NoError(t, err)

	_, err = NewEnvironment("bla", "0xfeeddeadbeefbeef")
	require.Error(t, err)

	_, err = NewEnvironment("bla", "")
	require.Error(t, err)

	_, err = NewEnvironment("aws", "")
	require.Error(t, err)

	var e *Environment
	e, err = NewEnvironment("", "")
	if err != nil {
		require.Nil(t, e)
	} else {
		require.NotNil(t, e)
		require.NotEqual(t, envUnspec, e.envType)
	}
}
