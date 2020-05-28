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


class FakeCrypto(object):
    def __init__(self):
        pass

    def __getattr__(self, name):
        logger.warning('loading {}'.format(name))


def test_load_crypto():
    from DeDRM_plugin.ineptepub import _load_crypto
    from mock import patch
    with patch('DeDRM_plugin.ineptepub._load_crypto_libcrypto') as libcrypto, \
            patch('DeDRM_plugin.ineptepub._load_crypto_pycrypto') as pycrypto:
        libcrypto.return_value = (None, None)
        pycrypto.return_value = (None, None)
        _load_crypto()
        libcrypto.assert_called()
        pycrypto.assert_not_called()


def test_load_crypto_fallback():
    from DeDRM_plugin.ineptepub import _load_crypto
    from mock import patch
    with patch('DeDRM_plugin.ineptepub._load_crypto_libcrypto') as libcrypto, \
            patch('DeDRM_plugin.ineptepub._load_crypto_pycrypto') as pycrypto:
        libcrypto.side_effect = ImportError
        pycrypto.return_value = (None, None)
        _load_crypto()
        libcrypto.assert_called()
        pycrypto.assert_called()


def test_RSA_init():
    from mock import patch, MagicMock, PropertyMock
    with patch('ctypes.CDLL') as loader_mock, \
            patch('ctypes.POINTER', side_effect=lambda a: a), \
            patch('ctypes.cast', side_effect=lambda a, b: a), \
            patch('ctypes.c_char_p', side_effect=lambda a: a), \
            patch('ctypes.create_string_buffer', side_effect=lambda a: a):
        # provide crypto_mock as loaded library
        crypto_mock = MagicMock()
        loader_mock.return_value = crypto_mock
        # provide mocks for crypto functions attributes
        d2i_RSAPrivateKey_mock = MagicMock()
        crypto_mock.attach_mock(d2i_RSAPrivateKey_mock, 'd2i_RSAPrivateKey')
        restype_mock = PropertyMock()
        argtypes_mock = PropertyMock()
        type(d2i_RSAPrivateKey_mock).restype = restype_mock
        type(d2i_RSAPrivateKey_mock).argtypes = argtypes_mock
        (AES, RSA) = loadAES_RSA()
        der = b'marker'
        RSA(der)
        restype_mock.assert_called()
        argtypes_mock.assert_called()
        d2i_RSAPrivateKey_mock.assert_called_once_with(None, der, len(der))


ENCRYPTION_XML = """<?xml version="1.0"?>
<encryption xmlns="urn:oasis:names:tc:opendocument:xmlns:container">¬
  <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">¬
    <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>¬
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">¬
      <resource xmlns="http://ns.adobe.com/adept">urn:uuid:03ba87d8-0c62-43e5-803b-7bdbaf391a3c</resource>¬
    </KeyInfo>¬
    <CipherData>¬
      <CipherReference URI="path1"></CipherReference>¬
    </CipherData>¬
  </EncryptedData>¬
  <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">¬
    <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>¬
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">¬
      <resource xmlns="http://ns.adobe.com/adept">urn:uuid:03ba87d8-0c62-43e5-803b-7bdbaf391a3c</resource>¬
    </KeyInfo>¬
    <CipherData>¬
      <CipherReference URI="path2"></CipherReference>¬
    </CipherData>¬
  </EncryptedData>
</encryption>
"""


def test_decryptor():
    from mock import MagicMock, patch, call, sentinel
    from DeDRM_plugin.ineptepub import Decryptor
    import DeDRM_plugin.ineptepub
    AES = MagicMock()
    RSA = MagicMock()
    DeDRM_plugin.ineptepub.AES = AES
    DeDRM_plugin.ineptepub.RSA = RSA
    key_marker = b'key'
    d = Decryptor(key_marker, ENCRYPTION_XML)
    AES.assert_called_with(key_marker)
    assert len(d._encrypted) == 2
    assert six.b('path1') in d._encrypted
    assert six.b('path2') in d._encrypted

    encrypted_marker = b'encrypted'
    with patch('zlib.decompressobj') as zlib:
        # decompress return values untouched
        # flush append empty string
        dc = MagicMock()
        dc.decompress.side_effect = lambda a: a
        dc.flush.return_value = b''
        # install mock
        zlib.return_value = dc
        # perform decompress
        value = d.decompress(encrypted_marker)
        zlib.assert_called_with(-15)
        dc.decompress.has_calls(
            call(encrypted_marker),
            call(b'Z')
        )
        dc.flush.assert_called()
        # check that remaining bytes are appended when available
        assert value == encrypted_marker + b'Z'

        dc.decompress.side_effect = lambda a: a if a != b'Z' else b''
        value = d.decompress(encrypted_marker)
        zlib.assert_called_with(-15)
        dc.decompress.has_calls(
            call(encrypted_marker),
            call(b'Z')
        )
        dc.flush.assert_called()
        # in this case no reminaing byte is applied
        assert value == encrypted_marker

        with patch('DeDRM_plugin.ineptepub.Decryptor.decompress') as dd:
            dd.return_value = sentinel.decompress
            data_marker = b''.join(map(bytes, range(0, 30)))
            # last value is used to cut value
            # 3 -> last three bytes are cut
            cut = 3
            data_marker = data_marker + bytes([cut])
            decrypted = d.decrypt('path1', data_marker)
            # 16 first bytes are skipped to call decrypt
            assert AES.decrypt.is_called_with(data_marker[16:])
            # decrypted value is cut before decompress
            assert dd.is_called_with(data_marker[16:-cut])
            # returned value is decompress result
            assert decrypted == sentinel.decompress


def loadAES_RSA():
    from DeDRM_plugin.ineptepub import _load_crypto_libcrypto
    return _load_crypto_libcrypto()
