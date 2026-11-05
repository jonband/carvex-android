package io.github.iamr0s.carvex.carplay

import io.github.iamr0s.carvex.carplay.core.*

/** Successful source-Link trust is a separate gate from candidate AirPlay routing. */
internal fun WifiBootstrap.requireAuthenticatedBootstrap(experimentalIntegrityOnly:Boolean=false) {
    if (authentication?.accepted(experimentalIntegrityOnly) != true) SecurityRequirements.requireAaTrust()
}

/** The production caller passes the binding saved before endpoint discovery. */
fun WifiBootstrap.securityInputs(
    expectedBinding: SecurityBinding, metadata: ReceiverMetadata,
    networkReady: Boolean, endpointValidated: Boolean, pairedCapabilityGate: Boolean? = null,
    experimentalIntegrityOnly: Boolean = false,
    sourceContextCurrent: Boolean = true,
): SecurityInputs {
    if(!sourceContextCurrent)securityFailure(SecurityReason.STALE_CONTEXT,phase="bootstrap-context")
    val source = authentication ?: securityFailure(SecurityReason.SECURITY_INPUT_MISSING,phase="bootstrap-context")
    val endpoint = endpoint ?: securityFailure(SecurityReason.SECURITY_INPUT_MISSING,phase="endpoint-resolution")
    val binding = expectedBinding.copy(generation=source.generation,epoch=source.epoch)
    // The user's explicit v11 experiment permits a bounded HAP attempt after scoped
    // discovery too. This local profile is not a peer capability or production trust.
    val gate=pairedCapabilityGate ?: ExperimentalHapDiscovery.gate(this,metadata,expectedBinding,
        networkReady,endpointValidated,experimentalIntegrityOnly)
    return SecurityInputs(binding, expectedBinding=expectedBinding, controlVersion=source.controlVersion,
        bootstrapTransport=bootstrapTransport, endpointSource=endpoint.source,
        startReady=startSessionReady, bootstrapAuthenticationAccepted=source.accepted(experimentalIntegrityOnly),
        networkReady=networkReady, endpointValidated=endpointValidated,
        features=metadata.effectiveFeatures, pairedCapabilityGate=gate,
        peerHintPresent=metadata.pairingId?.isNotEmpty()==true || startSessionReady,
        setupProviderBound=true, featureEvidence=metadata.effectiveFeatureEvidence)
}

/** A candidate only: setup/verify, historical key pins and live epoch gates remain mandatory. */
internal object ExperimentalHapDiscovery {
    fun gate(config:WifiBootstrap,metadata:ReceiverMetadata,binding:SecurityBinding,
             networkReady:Boolean,endpointValidated:Boolean,enabled:Boolean):Boolean? {
        if(!enabled||config.startSessionReady||config.bootstrapTransport!=SecurityTransport.BLUETOOTH_WIFI||
            config.endpointSource!=SecurityEntry.DISCOVERY||!networkReady||!endpointValidated)return null
        val auth=config.authentication?:return null
        if(auth.generation!=binding.generation||auth.epoch!=binding.epoch||!auth.challengeSignatureVerified)return null
        if(metadata.effectiveFeatureEvidence.has(38)!=true)return null
        val pi=metadata.pairingId?:return null
        if(pi.isBlank()||pi.toByteArray(Charsets.UTF_8).size !in 1..1024||metadata.publicKey?.size!=32)return null
        val endpoint=config.endpoint?:return null
        if(metadata.endpoint==null||metadata.port!=endpoint.port)return null
        val sameAddress=runCatching{metadata.endpoint.address.contentEquals(IpLiteral.parse(endpoint.address).address.address)}.getOrDefault(false)
        if(!sameAddress)return null
        val device=metadata.deviceId?:return null
        val samePeer=runCatching{ReceiverIdentity.canonical(device)==ReceiverIdentity.canonical(endpoint.receiver)}.getOrDefault(false)
        return if(samePeer)true else null
    }
}
