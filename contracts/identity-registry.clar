;; Identity Registry Contract
;; Maintains cryptographic proofs of identity without storing sensitive personal data
;; Manages identity credentials, verification statuses, and certificate management

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-invalid-hash (err u103))
(define-constant err-expired (err u104))
(define-constant err-not-verified (err u105))
(define-constant err-unauthorized (err u106))
(define-constant err-invalid-signature (err u107))
(define-constant err-revoked (err u108))

;; Data Variables
(define-data-var contract-admin principal tx-sender)
(define-data-var total-identities uint u0)
(define-data-var next-credential-id uint u1)
(define-data-var registry-paused bool false)

;; Data Maps
;; Core identity registry mapping identity hash to basic info
(define-map identity-registry
  { identity-hash: (buff 20) }
  {
    owner: principal,
    created-at: uint,
    last-updated: uint,
    verification-level: uint, ;; 0=unverified, 1=basic, 2=enhanced, 3=premium
    status: (string-ascii 20), ;; active, suspended, revoked
    metadata-hash: (buff 32) ;; Hash of off-chain metadata
  }
)

;; Identity credentials (multiple per identity)
(define-map identity-credentials
  { credential-id: uint }
  {
    identity-hash: (buff 20),
    credential-type: (string-ascii 50), ;; passport, drivers-license, ssn, etc.
    issuer: (string-ascii 100),
    credential-hash: (buff 32), ;; Hash of the actual credential data
    issued-at: uint,
    expires-at: uint,
    verification-status: (string-ascii 20), ;; pending, verified, rejected, expired
    verifier: (optional principal)
  }
)

;; Identity attestations from trusted parties
(define-map identity-attestations
  { identity-hash: (buff 20), attester: principal }
  {
    attestation-type: (string-ascii 50),
    confidence-level: uint, ;; 1-100 scale
    attestation-data: (buff 32), ;; Hash of attestation details
    created-at: uint,
    expires-at: uint,
    revoked: bool
  }
)

;; Trusted attesters (government agencies, financial institutions, etc.)
(define-map trusted-attesters
  { attester: principal }
  {
    organization-name: (string-ascii 100),
    attestation-types: (list 10 (string-ascii 50)),
    trust-level: uint, ;; 1-10 scale
    active: bool,
    registered-at: uint
  }
)

;; Identity linking (allows multiple addresses for same identity)
(define-map identity-links
  { primary-hash: (buff 20), linked-hash: (buff 20) }
  {
    link-type: (string-ascii 20), ;; primary, secondary, recovery
    linked-at: uint,
    verified: bool
  }
)

;; Verification requests
(define-map verification-requests
  { request-id: uint }
  {
    identity-hash: (buff 20),
    requester: principal,
    verification-type: (string-ascii 50),
    request-data: (buff 32),
    status: (string-ascii 20), ;; pending, approved, rejected, expired
    requested-at: uint,
    processed-at: uint,
    processor: (optional principal)
  }
)

(define-data-var next-request-id uint u1)

;; Identity activity log
(define-map identity-activity
  { activity-id: uint }
  {
    identity-hash: (buff 20),
    activity-type: (string-ascii 50),
    actor: principal,
    activity-data: (buff 32),
    timestamp: uint
  }
)

(define-data-var next-activity-id uint u1)

;; Read-only functions

;; Get identity information by hash
(define-read-only (get-identity (identity-hash (buff 20)))
  (map-get? identity-registry { identity-hash: identity-hash })
)

;; Get credential information
(define-read-only (get-credential (credential-id uint))
  (map-get? identity-credentials { credential-id: credential-id })
)

;; Get attestation information
(define-read-only (get-attestation (identity-hash (buff 20)) (attester principal))
  (map-get? identity-attestations { identity-hash: identity-hash, attester: attester })
)

;; Check if attester is trusted
(define-read-only (is-trusted-attester (attester principal))
  (match (map-get? trusted-attesters { attester: attester })
    attester-data (get active attester-data)
    false
  )
)

;; Get verification request
(define-read-only (get-verification-request (request-id uint))
  (map-get? verification-requests { request-id: request-id })
)

;; Check if identity is verified at specified level
(define-read-only (is-identity-verified (identity-hash (buff 20)) (min-level uint))
  (match (get-identity identity-hash)
    identity-data 
    (and (>= (get verification-level identity-data) min-level)
         (is-eq (get status identity-data) "active"))
    false
  )
)

;; Get identity activity
(define-read-only (get-activity (activity-id uint))
  (map-get? identity-activity { activity-id: activity-id })
)

;; Get total registered identities
(define-read-only (get-total-identities)
  (var-get total-identities)
)

;; Check if registry is paused
(define-read-only (is-registry-paused)
  (var-get registry-paused)
)

;; Verify identity ownership
(define-read-only (verify-identity-ownership (identity-hash (buff 20)) (claimed-owner principal))
  (match (get-identity identity-hash)
    identity-data (is-eq (get owner identity-data) claimed-owner)
    false
  )
)

;; Public functions

;; Register a new identity
(define-public (register-identity (identity-hash (buff 20)) (metadata-hash (buff 32)))
  (begin
    (asserts! (not (var-get registry-paused)) (err u109))
    (asserts! (is-none (get-identity identity-hash)) err-already-exists)
    
    (map-set identity-registry
      { identity-hash: identity-hash }
      {
        owner: tx-sender,
        created-at: stacks-block-height,
        last-updated: stacks-block-height,
        verification-level: u0,
        status: "active",
        metadata-hash: metadata-hash
      }
    )
    
    ;; Log activity
    (log-identity-activity identity-hash "identity-registered" tx-sender metadata-hash)
    
    (var-set total-identities (+ (var-get total-identities) u1))
    (ok identity-hash)
  )
)

;; Add credential to identity
(define-public (add-credential (identity-hash (buff 20)) (credential-type (string-ascii 50))
                              (issuer (string-ascii 100)) (credential-hash (buff 32))
                              (expires-at uint))
  (begin
    (asserts! (not (var-get registry-paused)) (err u109))
    (asserts! (verify-identity-ownership identity-hash tx-sender) err-unauthorized)
    
    (let ((credential-id (var-get next-credential-id)))
      
      (map-set identity-credentials
        { credential-id: credential-id }
        {
          identity-hash: identity-hash,
          credential-type: credential-type,
          issuer: issuer,
          credential-hash: credential-hash,
          issued-at: stacks-block-height,
          expires-at: expires-at,
          verification-status: "pending",
          verifier: none
        }
      )
      
      ;; Update identity last-updated timestamp
      (update-identity-timestamp identity-hash)
      
      ;; Log activity
      (log-identity-activity identity-hash "credential-added" tx-sender credential-hash)
      
      (var-set next-credential-id (+ credential-id u1))
      (ok credential-id)
    )
  )
)

;; Verify a credential (only by trusted attesters or admin)
(define-public (verify-credential (credential-id uint) (verification-status (string-ascii 20)))
  (begin
    (asserts! (or (is-eq tx-sender (var-get contract-admin))
                  (is-trusted-attester tx-sender)) err-unauthorized)
    
    (let ((credential-data (unwrap! (get-credential credential-id) err-not-found)))
      
      (map-set identity-credentials
        { credential-id: credential-id }
        (merge credential-data {
          verification-status: verification-status,
          verifier: (some tx-sender)
        })
      )
      
      ;; Update verification level if credential is verified
      (if (is-eq verification-status "verified")
        (update-verification-level (get identity-hash credential-data))
        true
      )
      
      ;; Log activity
      (log-identity-activity (get identity-hash credential-data) 
                           "credential-verified" tx-sender 
                           (get credential-hash credential-data))
      
      (ok true)
    )
  )
)

;; Create attestation for identity
(define-public (create-attestation (identity-hash (buff 20)) (attestation-type (string-ascii 50))
                                  (confidence-level uint) (attestation-data (buff 32))
                                  (expires-at uint))
  (begin
    (asserts! (is-trusted-attester tx-sender) err-unauthorized)
    (asserts! (is-some (get-identity identity-hash)) err-not-found)
    (asserts! (<= confidence-level u100) (err u110))
    
    (map-set identity-attestations
      { identity-hash: identity-hash, attester: tx-sender }
      {
        attestation-type: attestation-type,
        confidence-level: confidence-level,
        attestation-data: attestation-data,
        created-at: stacks-block-height,
        expires-at: expires-at,
        revoked: false
      }
    )
    
    ;; Update verification level based on attestation
    (update-verification-level identity-hash)
    
    ;; Log activity
    (log-identity-activity identity-hash "attestation-created" tx-sender attestation-data)
    
    (ok true)
  )
)

;; Revoke attestation
(define-public (revoke-attestation (identity-hash (buff 20)))
  (begin
    (let ((attestation-data (unwrap! (get-attestation identity-hash tx-sender) err-not-found)))
      
      (map-set identity-attestations
        { identity-hash: identity-hash, attester: tx-sender }
        (merge attestation-data { revoked: true })
      )
      
      ;; Recalculate verification level
      (update-verification-level identity-hash)
      
      ;; Log activity
      (log-identity-activity identity-hash "attestation-revoked" tx-sender 
                           (get attestation-data attestation-data))
      
      (ok true)
    )
  )
)

;; Request verification
(define-public (request-verification (identity-hash (buff 20)) (verification-type (string-ascii 50))
                                    (request-data (buff 32)))
  (begin
    (asserts! (is-some (get-identity identity-hash)) err-not-found)
    
    (let ((request-id (var-get next-request-id)))
      
      (map-set verification-requests
        { request-id: request-id }
        {
          identity-hash: identity-hash,
          requester: tx-sender,
          verification-type: verification-type,
          request-data: request-data,
          status: "pending",
          requested-at: stacks-block-height,
          processed-at: u0,
          processor: none
        }
      )
      
      ;; Log activity
      (log-identity-activity identity-hash "verification-requested" tx-sender request-data)
      
      (var-set next-request-id (+ request-id u1))
      (ok request-id)
    )
  )
)

;; Process verification request
(define-public (process-verification-request (request-id uint) (status (string-ascii 20)))
  (begin
    (asserts! (or (is-eq tx-sender (var-get contract-admin))
                  (is-trusted-attester tx-sender)) err-unauthorized)
    
    (let ((request-data (unwrap! (get-verification-request request-id) err-not-found)))
      
      (map-set verification-requests
        { request-id: request-id }
        (merge request-data {
          status: status,
          processed-at: stacks-block-height,
          processor: (some tx-sender)
        })
      )
      
      ;; Log activity
      (log-identity-activity (get identity-hash request-data) 
                           "verification-processed" tx-sender 
                           (get request-data request-data))
      
      (ok true)
    )
  )
)

;; Link identities
(define-public (link-identity (primary-hash (buff 20)) (linked-hash (buff 20)) 
                             (link-type (string-ascii 20)))
  (begin
    (asserts! (verify-identity-ownership primary-hash tx-sender) err-unauthorized)
    (asserts! (verify-identity-ownership linked-hash tx-sender) err-unauthorized)
    (asserts! (not (is-eq primary-hash linked-hash)) (err u111))
    
    (map-set identity-links
      { primary-hash: primary-hash, linked-hash: linked-hash }
      {
        link-type: link-type,
        linked-at: stacks-block-height,
        verified: true
      }
    )
    
    ;; Log activity for both identities
    (log-identity-activity primary-hash "identity-linked" tx-sender linked-hash)
    (log-identity-activity linked-hash "identity-linked" tx-sender primary-hash)
    
    (ok true)
  )
)

;; Update identity status
(define-public (update-identity-status (identity-hash (buff 20)) (new-status (string-ascii 20)))
  (begin
    (asserts! (or (is-eq tx-sender (var-get contract-admin))
                  (verify-identity-ownership identity-hash tx-sender)) err-unauthorized)
    
    (let ((identity-data (unwrap! (get-identity identity-hash) err-not-found)))
      
      (map-set identity-registry
        { identity-hash: identity-hash }
        (merge identity-data {
          status: new-status,
          last-updated: stacks-block-height
        })
      )
      
      ;; Log activity
      (log-identity-activity identity-hash "status-updated" tx-sender 
                           (unwrap-panic (as-max-len? (unwrap-panic (to-consensus-buff? new-status)) u32)))
      
      (ok true)
    )
  )
)

;; Private helper functions

;; Update verification level based on credentials and attestations
(define-private (update-verification-level (identity-hash (buff 20)))
  (let ((identity-data (unwrap-panic (get-identity identity-hash)))
        (current-level (get verification-level identity-data)))
    ;; Simplified verification level calculation
    ;; In practice, this would be more sophisticated
    (let ((new-level (calculate-verification-level identity-hash)))
      
      (if (> new-level current-level)
        (map-set identity-registry
          { identity-hash: identity-hash }
          (merge identity-data {
            verification-level: new-level,
            last-updated: stacks-block-height
          })
        )
        true
      )
    )
  )
)

;; Calculate verification level based on credentials and attestations
(define-private (calculate-verification-level (identity-hash (buff 20)))
  ;; Simplified calculation - would be more complex in practice
  ;; Returns 1 for basic verification, 2 for enhanced, 3 for premium
  u1 ;; Placeholder implementation
)

;; Update identity timestamp
(define-private (update-identity-timestamp (identity-hash (buff 20)))
  (let ((identity-data (unwrap-panic (get-identity identity-hash))))
    
    (map-set identity-registry
      { identity-hash: identity-hash }
      (merge identity-data { last-updated: stacks-block-height })
    )
  )
)

;; Log identity activity
(define-private (log-identity-activity (identity-hash (buff 20)) (activity-type (string-ascii 50))
                                      (actor principal) (activity-data (buff 32)))
  (let ((activity-id (var-get next-activity-id)))
    
    (map-set identity-activity
      { activity-id: activity-id }
      {
        identity-hash: identity-hash,
        activity-type: activity-type,
        actor: actor,
        activity-data: activity-data,
        timestamp: stacks-block-height
      }
    )
    
    (var-set next-activity-id (+ activity-id u1))
  )
)

;; Admin functions

;; Register trusted attester
(define-public (register-trusted-attester (attester principal) (organization-name (string-ascii 100))
                                         (attestation-types (list 10 (string-ascii 50))) (trust-level uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (asserts! (<= trust-level u10) (err u112))
    
    (map-set trusted-attesters
      { attester: attester }
      {
        organization-name: organization-name,
        attestation-types: attestation-types,
        trust-level: trust-level,
        active: true,
        registered-at: stacks-block-height
      }
    )
    
    (ok true)
  )
)

;; Pause/unpause registry
(define-public (toggle-registry-pause)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (var-set registry-paused (not (var-get registry-paused)))
    (ok (var-get registry-paused))
  )
)

;; Update contract admin
(define-public (update-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (var-set contract-admin new-admin)
    (ok true)
  )
)

