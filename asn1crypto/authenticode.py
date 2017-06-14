from __future__ import unicode_literals, division, absolute_import, print_function
"""
ASN.1 type classes for Microsoft Authenticode signature structures. Adds extra
oid mapping and value parsing to asn1crypto.cms.ContentType()
asn1crypto.tsp.ContentInfo() and asn1crypto.cms.CMSAttribute().
"""

from .algos import (
    DigestInfo
)
from .core import (
    BitString,
    Choice,
    ObjectIdentifier,
    OctetString,
    Sequence,
    IA5String,
    BMPString,
    Null,
    Set,
    ObjectDescriptor,
    SequenceOf,
    SetOf,
    ParsableOctetString,
    Any,
    Integer
)
from .cms import (
    CMSAttributeType,
    ContentType,
    SetOfContentInfo,
    Time,
    CMSAttribute,
    SignerInfos
)
from .tsp import (
    ContentInfo,
    EncapsulatedContentInfo,
    TSTInfo
)


class SpcPeImageDataId(ObjectIdentifier):
    _map = {
        '1.3.6.1.4.1.311.2.1.15': 'spc_pe_image_data',
    }


class SpcPeImageFlags(BitString):
    _map = {
        0: 'include_resources',
        1: 'include_debug_info',
        2: 'include_import_address_table',
    }


class SpcSerializedObject(Sequence):
    _fields = [
        ('class_id', OctetString),
        ('serialized_data', OctetString)
    ]


class SpcString(Choice):
    _alternatives = [
        ('unicode', BMPString, {'tag_type': 'implicit', 'tag': 0}),
        ('ascii', IA5String, {'tag_type': 'implicit', 'tag': 1}),
    ]


class SpcLink(Choice):
    _alternatives = [
        ('url', IA5String, {'tag_type': 'implicit', 'tag': 0}),
        ('moniker', SpcSerializedObject, {'tag_type': 'implicit', 'tag': 1}),
        ('file', SpcString, {'tag_type': 'explicit', 'tag': 2}),
    ]


class SpcPeImageData(Sequence):
    _fields = [
    ]


class SpcPeImageData(Sequence):
    _fields = [
        ('flags', SpcPeImageFlags),
        # under specified in Authenticode Documentation
        ('file', SpcLink, {'tag_type': 'explicit', 'tag': 0}),
    ]


class SpcAttributeTypeAndOptionalValue(Sequence):
    _fields = [
        ('type', SpcPeImageDataId),  # SPC_PE_IMAGE_DATAOBJ OID (1.3.6.1.4.1.311.2.1.15)
        # incorrectly specified in Authenticode Documentation
        ('value', SpcPeImageData, {'optional': True})

    ]

class SpcIndirectDataContent(Sequence):
    _fields = [
        ('data', SpcAttributeTypeAndOptionalValue),
        ('message_digest', DigestInfo),
    ]


class SpcStatementType(SequenceOf):
    _child_spec = ObjectIdentifier


class SetOfSpcStatementType(SetOf):
    _child_spec = SpcStatementType


class SpcSpOpusInfo(Sequence):
    _fields = [
        ('program_name', SpcString, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('more_info', SpcLink,      {'tag_type': 'explicit', 'tag': 1, 'optional': True})
    ]


class SetOfSpcSpOpusInfo(SetOf):
    _child_spec = SpcSpOpusInfo


class SetOfGoToMeetingData(SetOf):
    _child_spec = Any


# catalog def found here: https://github.com/kirei/catt/blob/master/scripts/parse-microsoft-authroot.pl
class CatalogIDSequence(Sequence):
    _fields = [
        ('oid', ObjectIdentifier)
    ]

class OIDSequence(Sequence):
    _fields = [
        ('oid', ObjectIdentifier),
        ('null', Null)
    ]
class MemberKeyGeneric(SetOf):
    _child_spec = OctetString
class MemberKeyPurposeIdentifiers(SetOf):
    _child_spec = ParsableOctetString

class MemberKeyFriendlyName(SetOf):
    _child_spec = ParsableOctetString

class MemberInfoId(ObjectIdentifier):
    _map = {
        '1.3.6.1.4.1.311.10.11.9':  'oid_cert_prop_id_metaekus',
        '1.3.6.1.4.1.311.10.11.11': 'cert_friendly_name_prop_id',
        '1.3.6.1.4.1.311.10.11.20': 'oid_cert_key_identifier_prop_id',
        '1.3.6.1.4.1.311.10.11.29': 'oid_cert_subject_name_md5_hash_prop_id',
        '1.3.6.1.4.1.311.10.11.83': 'cert_root_program_cert_policies_prop_id',
        '1.3.6.1.4.1.311.10.11.98': 'oid_cert_prop_id_prefix_98',
        '1.3.6.1.4.1.311.10.11.105': 'oid_cert_prop_id_prefix_105',
    }

class MemberInfo(Sequence):
    _fields = [
        ('type', MemberInfoId),
        ('value', Any)
    ]
    _oid_pair = ('type', 'value')
    _oid_specs = {
        'oid_cert_prop_id_metaekus': MemberKeyPurposeIdentifiers,
        'cert_root_program_cert_policies_prop_id': MemberKeyPurposeIdentifiers,
        'oid_cert_key_identifier_prop_id': MemberKeyGeneric
        # 'cert_friendly_name_prop_id': MemberKeyFriendlyName
    }

class CatalogMemberSet(SetOf):
    _child_spec = MemberInfo

class CatalogMember(Sequence):
    _fields = [
        ('double_encoded', OctetString),
        ('catalog_member_set', CatalogMemberSet)
    ]

class CatalogList(SequenceOf):
    _child_spec = CatalogMember

class CatNameValue(Sequence):
    pass

class CertificateTrustList(Sequence):
    _fields = [
        ('catalog_list_oid', CatalogIDSequence),
        ('digest', Integer),
        ('time', Time),
        ('member_oid', OIDSequence),
        ('catalog_list', CatalogList),
        ('cat_name_value', CatNameValue, {'tag_type': 'explicit', 'tag': 0, 'optional': True})
    ]

# strange but true
SignerInfos._bad_tag = 18

# add mapping into existing cms.
CMSAttributeType._map['1.3.6.1.4.1.311.2.1.11'] = 'spc_statement_type'
CMSAttributeType._map['1.3.6.1.4.1.311.2.1.12'] = 'spc_sp_opus_info'
CMSAttributeType._map['1.2.840.113549.1.9.25.4'] = 'sequence_number'
CMSAttributeType._map['1.2.840.113549.1.9.15'] = 'rsa_smime_capabilities'
# Unknown Attributes:
# 1.3.6.1.4.1.311.10.3.28
# 1.3.6.1.4.1.311.15.1

# Still Unknown Certificate Extended Key Usage:
# 1.3.6.1.4.1.311.61.6.1
# 1.3.6.1.4.1.311.10.3.27


# New Timestamp  Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) Used in OSS
CMSAttributeType._map['1.3.6.1.4.1.311.2.4.1'] = 'spc_nested_signature'
CMSAttributeType._map['1.3.6.1.4.1.311.3.3.1'] = 'spc_rfc3161'
CMSAttributeType._map['1.3.6.1.4.1.311.10.3.28'] = 'platform_manifest_binary_id'
CMSAttributeType._map['1.3.6.1.4.1.3845.3.9876.1.1.1'] = 'gotomeeting_data'

ContentType._map['1.3.6.1.4.1.311.2.1.4'] = 'spc_indirect_data_content'
# ContentType._map['1.3.7.19.4.8.15.8.2.4'] = '1.3.7.19.4.8.15.8.2.4'
ContentType._map['1.3.6.1.4.1.311.10.1'] = 'certificate_trust_list' # szOID_CTL

ContentInfo._oid_specs['spc_indirect_data_content'] = SpcIndirectDataContent
# ContentInfo._oid_specs['1.3.7.19.4.8.15.8.2.4'] = SpcIndirectDataContent
ContentInfo._oid_specs['certificate_trust_list'] = CertificateTrustList


CMSAttribute._oid_specs['spc_sp_opus_info'] = SetOfSpcSpOpusInfo
CMSAttribute._oid_specs['spc_statement_type'] = SetOfSpcStatementType
CMSAttribute._oid_specs['spc_rfc3161'] = SetOfContentInfo
CMSAttribute._oid_specs['spc_nested_signature'] = SetOfContentInfo
CMSAttribute._oid_specs['gotomeeting_data'] = SetOfGoToMeetingData

EncapsulatedContentInfo._oid_specs['tst_info'] = TSTInfo