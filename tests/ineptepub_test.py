#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import logging

import mock
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
@mock.patch('tests.ineptepub_test.Stream')
def test_SafeUnbuffered(MockStream):
    """SafeUnbuffered outputs str untouched, and performs a flush
    """
    from DeDRM_plugin.ineptepub import SafeUnbuffered
    stream = Stream()
    stream.encoding = 'utf-8'
    b = SafeUnbuffered(stream)
    b.write('simple string')
    stream.flush.assert_called()
    stream.write.assert_called_with('simple string')


@mock.patch('tests.ineptepub_test.Stream')
def test_SafeUnbuffered_replace(MockStream):
    """python2: with a unicode output, unsupported chars are replaced by '?'
    """
    if six.PY3:
        pytest.skip('Python 2 test only')
    from DeDRM_plugin.ineptepub import SafeUnbuffered
    stream = Stream()
    stream.encoding = 'ascii'
    b = SafeUnbuffered(stream)
    b.write(u'é')
    stream.flush.assert_called()
    stream.write.assert_called_with('?')


# TODO: windows; is workaround still needed with python 3
@mock.patch('sys.argv', ['ineptepub.py', six.b('arg1'), six.u('arg2')])
def test_argv():
    """Arguments from argv are converted if needed to text type
    (python2: unicode, python3: str)"""
    from DeDRM_plugin.ineptepub import unicode_argv
    args = unicode_argv()
    assert args[1] == u'arg1'
    assert args[2] == u'arg2'
    assert type(args[1]) == six.text_type
    assert type(args[2]) == six.text_type


@mock.patch('ctypes.util.find_library', return_value=None)
def test_load_crypto_none(MockFindLibrary):
    """AdeptError if libcrypto cannot be loaded"""
    from DeDRM_plugin.ineptepub import _load_crypto_libcrypto
    from DeDRM_plugin.ineptepub import ADEPTError
    with pytest.raises(ADEPTError):
        _load_crypto_libcrypto()


class FakeCrypto(object):
    def __init__(self):
        pass

    def __getattr__(self, name):
        logger.warning('loading {}'.format(name))


@mock.patch('DeDRM_plugin.ineptepub._load_crypto_libcrypto')
@mock.patch('DeDRM_plugin.ineptepub._load_crypto_pycrypto')
def test_load_crypto(MockPycrypto, MockLibcrypto):
    """Check priority for pycrypto loading"""
    from DeDRM_plugin.ineptepub import _load_crypto
    # Pair is needed to allow code to unpack returned value
    MockLibcrypto.return_value = (None, None)
    MockPycrypto.return_value = (None, None)
    _load_crypto()
    MockLibcrypto.assert_called()
    MockPycrypto.assert_not_called()


@mock.patch('DeDRM_plugin.ineptepub._load_crypto_libcrypto')
@mock.patch('DeDRM_plugin.ineptepub._load_crypto_pycrypto')
def load_crypto_fallback(exception_type, MockPycrypto, MockLibcrypto):
    from DeDRM_plugin.ineptepub import _load_crypto
    # First option throws an import error
    MockLibcrypto.side_effect = exception_type
    # Pair is needed to allow code to unpack returned value
    MockPycrypto.return_value = (None, None)
    _load_crypto()
    MockLibcrypto.assert_called()
    MockPycrypto.assert_called()


def test_load_crypto_fallback_ImportError():
    """ImportError on library loading allows fallback to secondary choice"""
    load_crypto_fallback(ImportError)


def test_load_crypto_fallback_ADEPTError():
    """AdeptError on library loading allows fallback to secondary choice"""
    from DeDRM_plugin.ineptepub import ADEPTError
    load_crypto_fallback(ADEPTError)


def mock_ctypes(f):
    """Mock ctypes functions. First argument is a MagicMock returned for
    each CDLL call, so that <mock>.return_value.function_name can be
    used to check targetted function calls"""
    @mock.patch('ctypes.c_char_p', side_effect=lambda a: a)
    @mock.patch('ctypes.cast', side_effect=lambda a, b: a)
    @mock.patch('ctypes.POINTER', side_effect=lambda a: a)
    @mock.patch('ctypes.create_string_buffer', side_effect=lambda a: a)
    @mock.patch('ctypes.CDLL')
    def wrapper(CDLL, create_string_buffer, POINTER, cast, c_char_p,
                *args, **kwargs):
        # only retains CDLL mock
        custom_args = list(args)
        custom_args.insert(0, create_string_buffer)
        custom_args.insert(0, CDLL.return_value)
        return f(*custom_args, **kwargs)
    return wrapper


@mock_ctypes
def test_RSA_init(libcrypto, create_buffer_string):
    """RSA init uses d2i_RSAPrivateKey to initialize rsa key from binary
    input.
    """
    (AES, RSA) = loadAES_RSA()
    der = b'marker'
    RSA(der)
    assert libcrypto.d2i_RSAPrivateKey.restype is not None
    assert len(libcrypto.d2i_RSAPrivateKey.argtypes) == 3
    libcrypto.d2i_RSAPrivateKey.assert_called_once_with(
        None, der, len(der))


@mock_ctypes
def test_RSA_free(libcrypto, create_buffer_string):
    """Check that rsa key (ctypes structure) is released when python object
    is deleted"""
    (AES, RSA) = loadAES_RSA()
    der = b'marker'
    libcrypto.d2i_RSAPrivateKey.return_value = mock.sentinel.rsa
    rsa = RSA(der)
    del rsa
    assert libcrypto.RSA_free.is_called_with(mock.sentinel.rsa)


@mock_ctypes
def test_RSA_init_failure(libcrypto, create_buffer_string):
    from DeDRM_plugin.ineptepub import ADEPTError
    """Check that d2i_RSAPrivateKey failure (null value) triggers an
    ADEPTError"""
    (AES, RSA) = loadAES_RSA()
    der = b'marker'
    libcrypto.d2i_RSAPrivateKey.return_value = None
    with pytest.raises(ADEPTError):
        RSA(der)


@mock_ctypes
def test_RSA_decrypt(libcrypto, create_buffer_string):
    (AES, RSA) = loadAES_RSA()
    # first init object
    der = b'marker'
    rsa = RSA(der)

    # prepare mock values (result buffer, size of decrypted buffer)
    buffer = b'abcdefghijklmnopqrst'
    size = 10
    # RSA_private_decrypt returns the decrypted value length
    libcrypto.RSA_private_decrypt.return_value = size
    rsa._rsa = mock.sentinel.rsa
    # create_buffer_string is responsible to initialize result buffer
    # push our own result
    create_buffer_string.return_value = buffer
    create_buffer_string.side_effect = None

    # decrypt, check RSA_* calls and check that returned value is
    # correctly split
    from_ = b''
    result = rsa.decrypt(from_)
    libcrypto.RSA_size.assert_called_with(mock.sentinel.rsa)
    libcrypto.RSA_private_decrypt.assert_called_with(
      len(from_), from_, buffer, mock.sentinel.rsa, 3  # RSA_NO_PADDING
    )
    assert result == buffer[:10]


@mock_ctypes
def test_RSA_decrypt_failure(libcrypto, create_buffer_string):
    from DeDRM_plugin.ineptepub import ADEPTError
    (AES, RSA) = loadAES_RSA()
    # first init object
    rsa = RSA(b'')
    # negative value for errors
    libcrypto.RSA_private_decrypt.return_value = -1
    with pytest.raises(ADEPTError):
        rsa.decrypt(b'')


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


def test_decryptor_decompress():
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
