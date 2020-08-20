#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import logging

import mock
import pytest
import six


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
if six.PY2:
    BUILTINS = '__builtin__'
else:
    BUILTINS = 'builtins'


def tst_empty():
    pass


@mock.patch('DeDRM_plugin.ineptpdf.RSA')
@mock.patch('DeDRM_plugin.ineptpdf.AES')
@mock.patch('DeDRM_plugin.ineptpdf.PDFSerializer')
@mock.patch(BUILTINS + '.open')
def test_decryptBook(open, PDFSerializer, AES, RSA):
    from DeDRM_plugin.ineptpdf import decryptBook
    from mock import sentinel
    decryptBook(sentinel.userkey, sentinel.inpath, sentinel.outpath)
    open.assert_has_calls([
        mock.call(sentinel.inpath, 'rb'),
        mock.call().__enter__(),  # enter call is needed
        mock.call(sentinel.outpath, 'wb')])
    PDFSerializer.return_value.dump.assert_called_with(
        open.return_value.__enter__.return_value)


@mock.patch('DeDRM_plugin.ineptpdf.PDFDocument')
@mock.patch('DeDRM_plugin.ineptpdf.PDFParser')
def test_PDFSerializer___init__(PDFParser, PDFDocument):
    """Check objids and trailer cleaning
    Prev key is removed from trailer
    XRefStm is removed from trailer
    Encrypt is removed from from trailer, corresponding objid is removed from
      objids
    """
    from DeDRM_plugin.ineptpdf import PDFSerializer
    from mock import sentinel
    inf = mock.MagicMock()
    xref1 = mock.MagicMock()
    xref2 = mock.MagicMock()
    encrypt = mock.MagicMock()
    encrypt.objid = sentinel.encryptObjId
    xref1.objids.return_value = [sentinel.objid1, sentinel.encryptObjId]
    xref2.objids.return_value = [sentinel.objid2]
    xref1.trailer = {
        sentinel.key: sentinel.value,
        'Prev': sentinel.Prev,
        'XRefStm': sentinel.XRefStm,
        'Encrypt': encrypt
    }
    xref2.trailer = {sentinel.key: sentinel.value}
    PDFDocument.return_value.xrefs = [xref1, xref2]

    # perform PDFSerializer init
    ser = PDFSerializer(inf, sentinel.userkey)
    inf.read.assert_called_with(8)
    inf.seek.assert_called()
    PDFDocument.assert_called()
    PDFParser.assert_called_with(PDFDocument.return_value, inf)
    PDFDocument.return_value.initialize.assert_called_with(sentinel.userkey)
    # ser.trailer is cleaned of Prev, XRefStm, Encrypt items
    assert len(ser.trailer) == 1
    assert ser.trailer == {sentinel.key: sentinel.value}
    # objids is cleaned of Encrypt related objid
    assert len(ser.objids) == 2
    assert ser.objids == set([sentinel.objid2, sentinel.objid1])


@mock.patch('DeDRM_plugin.ineptpdf.PDFDocument')
@mock.patch('DeDRM_plugin.ineptpdf.PDFParser')
def test_PDFSerializer_dump(PDFParser, PDFDocument):
    """Dump performs the following ops
    * write file headers
    * iterate over objids; retrieve associated obj
      * if PDFObjStmRef: add to xrefs output dict, key objid
      * else create an entry (position, genno) in xrefs and append content
        (serialize_indirect(objid, obj))
      * when genno is not available, fallback to 0 (genno seems to be a
        revision number)
    * extract position. This position will be startxref position
    * based on gen_xref_stm (global variable, set by __init__), we generate
      a xref or a xref stream
    * xref: header, number of elements, then for each objid (integer sequence)
      found in xrefs, write an entry, then ends with trailer and EOF marker
      * entry: 10 padded position, 5 padded revision, n or f
      * n: used; f: not used
      * extracted genno is never used. replaced by 0
      * for objid not in xrefs, position=0,revision=65535,f is inserted
      * startxref points to xref, followed by trailer
    * xref stream: see next test

    Some background:
    * tell() gives file position; it is used to insert in xref table "address"
      of objects
    * effective decryption is done by serialize_object, called by
      serialize_indirect when obj are written in the output document
    """
    from DeDRM_plugin.ineptpdf import PDFSerializer, PDFDocument, PDFObjStmRef
    xref = mock.MagicMock()
    xref.objids.return_value = [1, 2]
    objs = {}
    objs[1] = mock.MagicMock()
    objs[2] = mock.MagicMock()
    PDFDocument.return_value.xrefs = [ xref ]
    PDFDocument.return_value.getobj.side_effect = objs.__getitem__
    serializer = mock.MagicMock(spec=PDFSerializer)
    serializer.tell.return_value = 3
    serializer.doc = PDFDocument()
    serializer.objids = [1, 2]
    serializer.version = mock.sentinel.version
    serializer.trailer = [['Extra', 'Test']]
    PDFSerializer.dump(serializer, mock.MagicMock())
    serializer.tell.assert_has_calls([mock.call(), mock.call()])
    serializer.write.assert_has_calls([
            mock.call(mock.sentinel.version),
            mock.call(b'\n%\xe2\xe3\xcf\xd3\n'),
            mock.call(b'xref\n'),
            # max(objid) + 1 = 2 + 1 = 3
            mock.call(b'0 3\n'),
            # 0 is missing
            mock.call(b'0000000000 65535 f \n'),
            # 3 is from mocked self.tell
            mock.call(b'0000000003 00000 n \n'),
            mock.call(b'0000000003 00000 n \n'),
            mock.call(b'trailer\n'),
            # 3 is from mocked self.tell
            mock.call(b'\nstartxref\n3\n%%EOF')
            ])
    serializer.serialize_indirect.assert_has_calls([
        mock.call(1, objs[1]),
        mock.call(2, objs[2])
    ])
    serializer.serialize_object.assert_has_calls([
        # original trailer with updated size
        mock.call({'Size':3, 'Extra':'Test'})
    ])


@mock.patch('DeDRM_plugin.ineptpdf.PDFDocument')
@mock.patch('DeDRM_plugin.ineptpdf.PDFParser')
@mock.patch('zlib.compress')
def test_PDFSerializer_dump_xref_stm(compress, PDFParser, PDFDocument):
    """Dump performs the following ops
    * xref stream:
      * maxoffset is max of startxref position and maxobj position
      * increase fl2 so that (65536 + (fl2 - 2)*256) > maxoffset
      * increase fl3 so that (256 + (fl3 - 1)*256) > maxindex
      * for earch objid, data is:
        * 2 (PDFObjStmRef) or 1 (data)
        * stmid or data
        * index or revision number set to 0
        * stmid and index are split to get rid for extra bytes (fl2, fl3)
      * data is compressed with zlib
      * dic stores information for decoding, including fl2 and fl3, and index
        that lists consecutives indexes (if indexes range [1,n], index is
        [[1,n]])
      * PDFStream is used with dic and data to obtain a PDF object to serialize
      * startxref points to PDFStream
    """
    from DeDRM_plugin.ineptpdf import PDFSerializer, PDFDocument, PDFObjStmRef, gen_xref_stm
    import DeDRM_plugin.ineptpdf
    DeDRM_plugin.ineptpdf.gen_xref_stm = True
    xref = mock.MagicMock()
    xref.objids.return_value = [1, 2]
    objs = {}
    objs[1] = mock.MagicMock()
    objs[2] = mock.MagicMock()
    PDFDocument.return_value.xrefs = [ xref ]
    PDFDocument.return_value.getobj.side_effect = objs.__getitem__
    serializer = mock.MagicMock(spec=PDFSerializer)
    serializer.tell.return_value = 3
    serializer.doc = PDFDocument()
    serializer.objids = [1, 2]
    serializer.version = mock.sentinel.version
    serializer.trailer = [['Extra', 'Test'], ['Root', 'RootValue']]
    PDFSerializer.dump(serializer, mock.MagicMock())
    serializer.tell.assert_has_calls([mock.call(), mock.call()])
    serializer.write.assert_has_calls([
            mock.call(mock.sentinel.version),
            mock.call(b'\n%\xe2\xe3\xcf\xd3\n'),
            mock.call(b'startxref\n3\n%%EOF')
            ])
    serializer.serialize_indirect.assert_has_calls([
        mock.call(1, objs[1]),
        mock.call(2, objs[2])
    ])
    compress.assert_has_calls([mock.call()])
