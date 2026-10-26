@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console output is the point: it ends up in the Packer build log
        'PSAvoidUsingWriteHost',
        # Every control script takes $Context so the engine can call them all the same way
        'PSReviewUnusedParameter',
        # Set-RegistryBaseline is an internal helper, not an interactive cmdlet
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
