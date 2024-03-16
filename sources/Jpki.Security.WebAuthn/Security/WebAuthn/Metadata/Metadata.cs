//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace Jpki.Security.WebAuthn.Security.WebAuthn.Metadata
//{

//    /// <summary>
//    /// Represents the MetadataBLOBPayload.
//    /// </summary>
//    public class Root
//    {
//        [JsonConstructor]
//        public Root(
//            [JsonProperty("legalHeader")] string legalHeader,
//            [JsonProperty("no")] int no,
//            [JsonProperty("nextUpdate")] string nextUpdate,
//            [JsonProperty("entries")] List<Entry> entries
//        )
//        {
//            this.LegalHeader = legalHeader;
//            this.No = no;
//            this.NextUpdate = nextUpdate;
//            this.Entries = entries;
//        }

//        /// <summary>
//        /// Indication of the acceptance of the relevant legal agreement for using the MDS.
//        /// </summary>
//        [JsonProperty("legalHeader")]
//        public string LegalHeader { get; }

//        /// <summary>
//        /// The serial number of this UAF Metadata BLOB Payload.
//        /// </summary>
//        [JsonProperty("no")]
//        public int No { get; }

//        /// <summary>
//        /// Date when the next update will be provided at latest.
//        /// </summary>
//        [JsonProperty("nextUpdate")]
//        public DateTimeOffset? NextUpdate { get; }

//        [JsonProperty("entries")]
//        public IReadOnlyList<Entry> Entries { get; }
//    }

//    /// <summary>
//    /// Represents the MetadataBLOBPayloadEntry.
//    /// </summary>
//    public class Entry
//    {
//        [JsonConstructor]
//        public Entry(
//            [JsonProperty("aaid")] string aaid,
//            [JsonProperty("aaguid")] string aaguid,
//            [JsonProperty("attestationCertificateKeyIdentifiers")] List<string> attestationCertificateKeyIdentifiers,
//            [JsonProperty("metadataStatement")] MetadataStatement metadataStatement,
//            [JsonProperty("statusReports")] List<StatusReport> statusReports,
//            [JsonProperty("timeOfLastStatusChange")] DateTimeOffset timeOfLastStatusChange
//        )
//        {
//            this.Aaguid = aaguid;
//            this.MetadataStatement = metadataStatement;
//            this.StatusReports = statusReports;
//            this.TimeOfLastStatusChange = timeOfLastStatusChange;
//            this.AttestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
//            this.Aaid = aaid;
//        }

//        /// <summary>
//        /// The AAID of the authenticator this metadata BLOB payload entry relates to. 
//        /// See [UAFProtocol] for the definition of the AAID structure. 
//        /// </summary>
//        /// 
//        [JsonProperty("aaid")]
//        public string Aaid { get; }

//        /// <summary>
//        /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the
//        /// definition of the AAGUID structure.
//        /// </summary>
//        [JsonProperty("aaguid")]
//        public string Aaguid { get; }

//        /// <summary>
//        /// A list of the attestation certificate public key identifiers.
//        /// </summary>
//        [JsonProperty("attestationCertificateKeyIdentifiers")]
//        public IReadOnlyList<string> AttestationCertificateKeyIdentifiers { get; }

//        /// <summary>
//        /// The metadata statement as defined in [FIDOMetadataStatement].
//        /// </summary>
//        [JsonProperty("metadataStatement")]
//        public MetadataStatement MetadataStatement { get; }

//        /// <summary>
//        /// Status reports applicable to this authenticator.
//        /// </summary>
//        [JsonProperty("statusReports")]
//        public IReadOnlyList<StatusReport> StatusReports { get; }

//        /// <summary>
//        /// Date since when the status report array was set to the current value.
//        /// </summary>
//        [JsonProperty("timeOfLastStatusChange")]
//        public DateTimeOffset? TimeOfLastStatusChange { get; }
//    }


//    public class Algorithm
//    {
//        [JsonConstructor]
//        public Algorithm(
//            [JsonProperty("type")] string type,
//            [JsonProperty("alg")] int alg
//        )
//        {
//            this.Type = type;
//            this.Alg = alg;
//        }

//        [JsonProperty("type")]
//        public string Type { get; }

//        [JsonProperty("alg")]
//        public int Alg { get; }
//    }



//    public class Certifications
//    {
//        [JsonConstructor]
//        public Certifications(
//            [JsonProperty("FIDO")] int? fIDO,
//            [JsonProperty("FIPS-CMVP-2")] int? fIPSCMVP2,
//            [JsonProperty("FIPS-CMVP-2-PHY")] int? fIPSCMVP2PHY
//        )
//        {
//            this.FIDO = fIDO;
//            this.FIPSCMVP2 = fIPSCMVP2;
//            this.FIPSCMVP2PHY = fIPSCMVP2PHY;
//        }

//        [JsonProperty("FIDO")]
//        public int? FIDO { get; }

//        [JsonProperty("FIPS-CMVP-2")]
//        public int? FIPSCMVP2 { get; }

//        [JsonProperty("FIPS-CMVP-2-PHY")]
//        public int? FIPSCMVP2PHY { get; }
//    }



//    public class Options
//    {
//        [JsonConstructor]
//        public Options(
//            [JsonProperty("rk")] bool rk,
//            [JsonProperty("clientPin")] bool clientPin,
//            [JsonProperty("up")] bool up,
//            [JsonProperty("uv")] bool uv,
//            [JsonProperty("plat")] bool? plat,
//            [JsonProperty("pinUvAuthToken")] bool? pinUvAuthToken,
//            [JsonProperty("noMcGaPermissionsWithClientPin")] bool? noMcGaPermissionsWithClientPin,
//            [JsonProperty("bioEnroll")] bool? bioEnroll,
//            [JsonProperty("userVerificationMgmtPreview")] bool? userVerificationMgmtPreview,
//            [JsonProperty("uvBioEnroll")] bool? uvBioEnroll,
//            [JsonProperty("credMgmt")] bool? credMgmt,
//            [JsonProperty("credentialMgmtPreview")] bool? credentialMgmtPreview,
//            [JsonProperty("makeCredUvNotRqd")] bool? makeCredUvNotRqd,
//            [JsonProperty("authnrCfg")] bool? authnrCfg,
//            [JsonProperty("alwaysUv")] bool? alwaysUv,
//            [JsonProperty("largeBlobs")] bool? largeBlobs,
//            [JsonProperty("setMinPINLength")] bool? setMinPINLength,
//            [JsonProperty("ep")] bool? ep,
//            [JsonProperty("uvAcfg")] bool? uvAcfg
//        )
//        {
//            this.Rk = rk;
//            this.ClientPin = clientPin;
//            this.Up = up;
//            this.Uv = uv;
//            this.Plat = plat;
//            this.PinUvAuthToken = pinUvAuthToken;
//            this.NoMcGaPermissionsWithClientPin = noMcGaPermissionsWithClientPin;
//            this.BioEnroll = bioEnroll;
//            this.UserVerificationMgmtPreview = userVerificationMgmtPreview;
//            this.UvBioEnroll = uvBioEnroll;
//            this.CredMgmt = credMgmt;
//            this.CredentialMgmtPreview = credentialMgmtPreview;
//            this.MakeCredUvNotRqd = makeCredUvNotRqd;
//            this.AuthnrCfg = authnrCfg;
//            this.AlwaysUv = alwaysUv;
//            this.LargeBlobs = largeBlobs;
//            this.SetMinPINLength = setMinPINLength;
//            this.Ep = ep;
//            this.UvAcfg = uvAcfg;
//        }

//        [JsonProperty("rk")]
//        public bool Rk { get; }

//        [JsonProperty("clientPin")]
//        public bool ClientPin { get; }

//        [JsonProperty("up")]
//        public bool Up { get; }

//        [JsonProperty("uv")]
//        public bool Uv { get; }

//        [JsonProperty("plat")]
//        public bool? Plat { get; }

//        [JsonProperty("pinUvAuthToken")]
//        public bool? PinUvAuthToken { get; }

//        [JsonProperty("noMcGaPermissionsWithClientPin")]
//        public bool? NoMcGaPermissionsWithClientPin { get; }

//        [JsonProperty("bioEnroll")]
//        public bool? BioEnroll { get; }

//        [JsonProperty("userVerificationMgmtPreview")]
//        public bool? UserVerificationMgmtPreview { get; }

//        [JsonProperty("uvBioEnroll")]
//        public bool? UvBioEnroll { get; }

//        [JsonProperty("credMgmt")]
//        public bool? CredMgmt { get; }

//        [JsonProperty("credentialMgmtPreview")]
//        public bool? CredentialMgmtPreview { get; }

//        [JsonProperty("makeCredUvNotRqd")]
//        public bool? MakeCredUvNotRqd { get; }

//        [JsonProperty("authnrCfg")]
//        public bool? AuthnrCfg { get; }

//        [JsonProperty("alwaysUv")]
//        public bool? AlwaysUv { get; }

//        [JsonProperty("largeBlobs")]
//        public bool? LargeBlobs { get; }

//        [JsonProperty("setMinPINLength")]
//        public bool? SetMinPINLength { get; }

//        [JsonProperty("ep")]
//        public bool? Ep { get; }

//        [JsonProperty("uvAcfg")]
//        public bool? UvAcfg { get; }
//    }


//    public class StatusReport
//    {
//        [JsonConstructor]
//        public StatusReport(
//            [JsonProperty("status")] string status,
//            [JsonProperty("effectiveDate")] string effectiveDate,
//            [JsonProperty("certificationDescriptor")] string certificationDescriptor,
//            [JsonProperty("certificateNumber")] string certificateNumber,
//            [JsonProperty("certificationPolicyVersion")] string certificationPolicyVersion,
//            [JsonProperty("certificationRequirementsVersion")] string certificationRequirementsVersion,
//            [JsonProperty("url")] string url
//        )
//        {
//            this.Status = status;
//            this.EffectiveDate = effectiveDate;
//            this.CertificationDescriptor = certificationDescriptor;
//            this.CertificateNumber = certificateNumber;
//            this.CertificationPolicyVersion = certificationPolicyVersion;
//            this.CertificationRequirementsVersion = certificationRequirementsVersion;
//            this.Url = url;
//        }

//        [JsonProperty("status")]
//        public string Status { get; }

//        [JsonProperty("effectiveDate")]
//        public string EffectiveDate { get; }

//        [JsonProperty("certificationDescriptor")]
//        public string CertificationDescriptor { get; }

//        [JsonProperty("certificateNumber")]
//        public string CertificateNumber { get; }

//        [JsonProperty("certificationPolicyVersion")]
//        public string CertificationPolicyVersion { get; }

//        [JsonProperty("certificationRequirementsVersion")]
//        public string CertificationRequirementsVersion { get; }

//        [JsonProperty("url")]
//        public string Url { get; }
//    }




//}
