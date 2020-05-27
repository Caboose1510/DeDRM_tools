#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import logging

import pytest
import six


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


def test_ping():
    pass


class Stream(object):
    def __init__(self):
        self.encoding = None


logger.warning(Stream.__module__ + '.' + Stream.__name__)


# TODO SafeUnbuffered
# python 2: unicode converted to python2 str
# python 3: stdout/stderr only allow str
# python 3: should we allow bytes and print repr in this case ?
def test_SafeUnbuffered():
    """SafeUnbuffered outputs str untouched, and performs a flush
    """
    from DeDRM_plugin.ineptepub import SafeUnbuffered
    from mock import patch
    with patch('tests.ineptepub_test.Stream'):
        stream = Stream()
        stream.encoding = 'utf-8'
        b = SafeUnbuffered(stream)
        b.write('simple string')
        stream.flush.assert_called()
        stream.write.assert_called_with('simple string')


def test_SafeUnbuffered_replace():
    """python2: with a unicode output, unsupported chars are replaced by '?'
    """
    if six.PY3:
        pytest.skip('Python 2 test only')
    from DeDRM_plugin.ineptepub import SafeUnbuffered
    from mock import patch
    with patch('tests.ineptepub_test.Stream'):
        stream = Stream()
        stream.encoding = 'ascii'
        b = SafeUnbuffered(stream)
        b.write(u'é')
        stream.flush.assert_called()
        stream.write.assert_called_with('?')


# TODO: windows; is workaround still needed with python 3
def test_argv():
    """Arguments from argv are converted if needed to text type
    (python2: unicode, python3: str)"""
    from DeDRM_plugin.ineptepub import unicode_argv
    from mock import patch
    with patch('sys.argv', ['ineptepub.py', six.b('arg1'), six.u('arg2')]):
        args = unicode_argv()
        assert args[1] == u'arg1'
        assert args[2] == u'arg2'
        assert type(args[1]) == six.text_type
        assert type(args[2]) == six.text_type


def test_load_crypto_none():
    """AdeptError if libcrypto cannot be loaded"""
    from DeDRM_plugin.ineptepub import _load_crypto_libcrypto
    from DeDRM_plugin.ineptepub import ADEPTError
    from mock import patch
    with patch('ctypes.util.find_library', return_value=None):
        with pytest.raises(ADEPTError):
            _load_crypto_libcrypto()


def test_RSA_init():
    from mock import patch
    from crypto import d2i_RSAPrivateKey
    with patch('crypto.d2i_RSAPrivateKey'):
        RSA = loadAES_RSA()
        RSA(b'')
        d2i_RSAPrivateKey.assert_called()


def loadAES_RSA():
    from DeDRM_plugin.ineptepub import _load_crypto_libcrypto
    return _load_crypto_libcrypto()
