"""
Tests verifying the native ``xmlsec``/``libxmlsec1`` XML-DSig bindings are usable.

These guard against the class of failure this dependency is prone to in CI/build environments:
the C extension imports fine wherever ``libxmlsec1``, ``libxml2`` and their -dev headers are
present, but raises ``ImportError``/``OSError`` (missing shared library) or fails signing/
verification calls wherever they aren't.
"""

import datetime
import importlib.metadata
import unittest

import lxml.etree
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _generate_self_signed_cert():
    """
    Return (private_key_pem, cert_pem) for a throwaway, test-only self-signed certificate.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "xmlsec-integration-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


class TestXmlsecNativeBindings(unittest.TestCase):
    """
    Verifies that the ``xmlsec`` package and its native ``libxmlsec1`` bindings are usable.
    """

    def test_native_bindings_are_accessible(self):
        """
        The C-extension classes backed by libxmlsec1/libxml2 are accessible post-import.

        Merely reaching this line already proves ``libxmlsec1.so`` was found and loaded --
        `import xmlsec` fails with ``ImportError``/``OSError`` otherwise.
        """
        self.assertTrue(hasattr(xmlsec, 'Key'))
        self.assertTrue(hasattr(xmlsec, 'SignatureContext'))
        self.assertTrue(hasattr(xmlsec, 'template'))
        self.assertTrue(hasattr(xmlsec, 'Transform'))

    def test_installed_versions_match_pinned_requirements(self):
        """
        The installed ``xmlsec``/``lxml`` versions match what's pinned in requirements/base.txt.
        """
        with open('requirements/base.txt', encoding='utf8') as base_txt:
            pinned = dict(
                line.split('==', 1)
                for line in base_txt
                if '==' in line and not line.startswith(('#', ' '))
            )
        self.assertEqual(importlib.metadata.version('xmlsec'), pinned['xmlsec'].strip())
        self.assertEqual(importlib.metadata.version('lxml'), pinned['lxml'].strip())

    def test_sign_and_verify_xml_document_round_trip(self):
        """
        Sign an XML document and verify the signature, exercising the native libxmlsec1 C library
        end-to-end (not merely importing it).
        """
        key_pem, cert_pem = _generate_self_signed_cert()

        doc = lxml.etree.fromstring(
            b'<Envelope xmlns="urn:test"><Payload ID="payload-1">hello</Payload></Envelope>'
        )
        payload_node = doc[0]
        xmlsec.tree.add_ids(doc, ["ID"])

        signature_node = xmlsec.template.create(doc, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256)
        doc.append(signature_node)
        ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA256, uri="#payload-1")
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        key_info = xmlsec.template.ensure_key_info(signature_node)
        xmlsec.template.add_x509_data(key_info)

        sign_key = xmlsec.Key.from_memory(key_pem, xmlsec.KeyFormat.PEM)
        sign_key.load_cert_from_memory(cert_pem, xmlsec.KeyFormat.PEM)
        sign_ctx = xmlsec.SignatureContext()
        sign_ctx.key = sign_key
        sign_ctx.sign(signature_node)

        # A tampered payload must fail verification -- proves the check isn't a no-op.
        tampered_doc = lxml.etree.fromstring(lxml.etree.tostring(doc))
        tampered_doc[0].text = 'tampered'
        verify_key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)
        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.key = verify_key
        with self.assertRaises(xmlsec.Error):
            verify_ctx.verify(tampered_doc.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))

        # The untampered, signed document verifies successfully.
        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)
        verify_ctx.verify(doc.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))
        self.assertEqual(payload_node.text, 'hello')
