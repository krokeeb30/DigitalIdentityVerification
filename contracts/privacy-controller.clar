;; Privacy Controller Contract
;; Manages user consent and data access permissions
;; Controls what information is shared with which organizations
;; Handles data retention and deletion requests

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u300))
(define-constant err-not-found (err u301))
(define-constant err-unauthorized (err u302))
(define-constant err-already-exists (err u303))
(define-constant err-invalid-permission (err u304))
(define-constant err-consent-expired (err u305))
(define-constant err-data-retention-violation (err u306))
(define-constant err-invalid-scope (err u307))
(define-constant err-revoked-access (err u308))

;; Data Variables
(define-data-var contract-admin principal tx-sender)
(define-data-var global-privacy-enabled bool true)
(define-data-var next-consent-id uint u1)
(define-data-var next-access-log-id uint u1)
(define-data-var default-consent-duration uint u8640) ;; ~60 days in blocks
(define-data-var max-data-retention-period uint u52560) ;; ~1 year in blocks

;; Data Maps
;; User consent records
(define-map user-consents
  { identity-hash: (buff 20), data-requester: principal }
  {
    consent-id: uint,
    data-types: (list 20 (string-ascii 50)), ;; What data types are consented to
    purpose: (string-ascii 200), ;; Purpose of data usage
    consent-level: uint, ;; 1=basic, 2=detailed, 3=comprehensive
    granted-at: uint,
    expires-at: uint,
    revoked: bool,
    revoked-at: uint,
    consent-hash: (buff 32) ;; Hash of consent terms
  }
)

;; Privacy preferences per identity
(define-map privacy-preferences
  { identity-hash: (buff 20) }
  {
    default-consent-duration: uint,
    auto-consent-level: uint, ;; 0=no auto-consent, 1-3=consent levels
    data-sharing-restrictions: (list 10 (string-ascii 50)),
    notification-preferences: (string-ascii 20), ;; email, sms, none
    data-retention-preference: uint, ;; Maximum days to retain data
    third-party-sharing-allowed: bool,
    anonymization-required: bool,
    created-at: uint,
    updated-at: uint
  }
)

;; Access permissions (who can access what data)
(define-map access-permissions
  { identity-hash: (buff 20), accessor: principal, data-type: (string-ascii 50) }
  {
    permission-level: uint, ;; 1=read, 2=write, 3=delete
    granted-by: principal,
    granted-at: uint,
    expires-at: uint,
    usage-count: uint,
    max-usage: uint,
    last-accessed: uint,
    access-conditions: (list 5 (string-ascii 100))
  }
)

;; Data access audit log
(define-map access-audit-log
  { log-id: uint }
  {
    identity-hash: (buff 20),
    accessor: principal,
    data-type: (string-ascii 50),
    access-type: (string-ascii 20), ;; read, write, delete, export
    purpose: (string-ascii 200),
    result: (string-ascii 20), ;; granted, denied, limited
    timestamp: uint,
    ip-hash: (optional (buff 20)), ;; Hashed IP address
    user-agent-hash: (optional (buff 32)) ;; Hashed user agent
  }
)

;; Data retention policies
(define-map data-retention-policies
  { policy-id: uint }
  {
    policy-name: (string-ascii 100),
    data-types: (list 20 (string-ascii 50)),
    retention-period: uint, ;; in blocks
    deletion-method: (string-ascii 50), ;; secure-delete, anonymize, archive
    legal-basis: (string-ascii 200),
    created-by: principal,
    active: bool,
    created-at: uint
  }
)

(define-data-var next-policy-id uint u1)

;; Data subject requests (GDPR-style)
(define-map data-subject-requests
  { request-id: uint }
  {
    identity-hash: (buff 20),
    requester: principal,
    request-type: (string-ascii 50), ;; access, rectification, erasure, portability
    request-data: (buff 32),
    status: (string-ascii 20), ;; pending, processing, completed, rejected
    submitted-at: uint,
    deadline: uint, ;; Legal deadline for response
    processed-at: uint,
    processor: (optional principal),
    response-data: (optional (buff 32))
  }
)

(define-data-var next-subject-request-id uint u1)

;; Consent withdrawal tracking
(define-map consent-withdrawals
  { withdrawal-id: uint }
  {
    identity-hash: (buff 20),
    withdrawn-consent-id: uint,
    withdrawal-reason: (string-ascii 200),
    withdrawn-by: principal,
    withdrawn-at: uint,
    data-deletion-requested: bool,
    deletion-completed: bool,
    deletion-completed-at: uint
  }
)

(define-data-var next-withdrawal-id uint u1)

;; Third-party data processors
(define-map data-processors
  { processor: principal }
  {
    processor-name: (string-ascii 100),
    processor-type: (string-ascii 50), ;; analytics, marketing, support, etc.
    data-types: (list 20 (string-ascii 50)),
    processing-purposes: (list 10 (string-ascii 100)),
    retention-period: uint,
    security-certification: (string-ascii 100),
    privacy-policy-url: (string-ascii 200),
    active: bool,
    registered-at: uint
  }
)

;; Read-only functions

;; Get user consent
(define-read-only (get-user-consent (identity-hash (buff 20)) (data-requester principal))
  (map-get? user-consents { identity-hash: identity-hash, data-requester: data-requester })
)

;; Get privacy preferences
(define-read-only (get-privacy-preferences (identity-hash (buff 20)))
  (map-get? privacy-preferences { identity-hash: identity-hash })
)

;; Get access permission
(define-read-only (get-access-permission (identity-hash (buff 20)) (accessor principal) (data-type (string-ascii 50)))
  (map-get? access-permissions { identity-hash: identity-hash, accessor: accessor, data-type: data-type })
)

;; Check if access is allowed
(define-read-only (is-access-allowed (identity-hash (buff 20)) (accessor principal) (data-type (string-ascii 50)))
  (let ((consent-data (get-user-consent identity-hash accessor))
        (permission-data (get-access-permission identity-hash accessor data-type)))
    
    (and 
      ;; Check consent exists and is valid
      (match consent-data
        consent (and (not (get revoked consent))
                     (< stacks-block-height (get expires-at consent))
                     (is-some (index-of (get data-types consent) data-type)))
        false
      )
      ;; Check permission exists and is valid
      (match permission-data
        permission (and (< stacks-block-height (get expires-at permission))
                        (< (get usage-count permission) (get max-usage permission)))
        false
      )
    )
  )
)

;; Get access audit entry
(define-read-only (get-access-audit-entry (log-id uint))
  (map-get? access-audit-log { log-id: log-id })
)

;; Get data retention policy
(define-read-only (get-data-retention-policy (policy-id uint))
  (map-get? data-retention-policies { policy-id: policy-id })
)

;; Get data subject request
(define-read-only (get-data-subject-request (request-id uint))
  (map-get? data-subject-requests { request-id: request-id })
)

;; Get consent withdrawal
(define-read-only (get-consent-withdrawal (withdrawal-id uint))
  (map-get? consent-withdrawals { withdrawal-id: withdrawal-id })
)

;; Get data processor info
(define-read-only (get-data-processor (processor principal))
  (map-get? data-processors { processor: processor })
)

;; Check if consent is valid
(define-read-only (is-consent-valid (identity-hash (buff 20)) (data-requester principal))
  (match (get-user-consent identity-hash data-requester)
    consent-data
    (and (not (get revoked consent-data))
         (< stacks-block-height (get expires-at consent-data)))
    false
  )
)

;; Get consent expiration time
(define-read-only (get-consent-expiration (identity-hash (buff 20)) (data-requester principal))
  (match (get-user-consent identity-hash data-requester)
    consent-data (ok (get expires-at consent-data))
    err-not-found
  )
)

;; Public functions

;; Grant consent for data usage
(define-public (grant-consent (identity-hash (buff 20)) (data-requester principal)
                             (data-types (list 20 (string-ascii 50))) (purpose (string-ascii 200))
                             (consent-level uint) (duration-blocks uint))
  (begin
    ;; Only identity owner can grant consent
    (asserts! (is-identity-owner identity-hash tx-sender) err-unauthorized)
    (asserts! (<= consent-level u3) err-invalid-permission)
    (asserts! (<= duration-blocks (var-get max-data-retention-period)) err-data-retention-violation)
    
    (let ((consent-id (var-get next-consent-id))
          (expires-at (+ stacks-block-height duration-blocks))
          (consent-terms (concat identity-hash (unwrap-panic (to-consensus-buff? consent-id))))
          (consent-hash (hash160 consent-terms)))
      
      (map-set user-consents
        { identity-hash: identity-hash, data-requester: data-requester }
        {
          consent-id: consent-id,
          data-types: data-types,
          purpose: purpose,
          consent-level: consent-level,
          granted-at: stacks-block-height,
          expires-at: expires-at,
          revoked: false,
          revoked-at: u0,
          consent-hash: consent-hash
        }
      )
      
      ;; Log the consent granting
      (log-access-event identity-hash data-requester "consent-granted" purpose "granted")
      
      (var-set next-consent-id (+ consent-id u1))
      (ok consent-id)
    )
  )
)

;; Revoke consent
(define-public (revoke-consent (identity-hash (buff 20)) (data-requester principal))
  (begin
    (asserts! (is-identity-owner identity-hash tx-sender) err-unauthorized)
    
    (let ((consent-data (unwrap! (get-user-consent identity-hash data-requester) err-not-found))
          (withdrawal-id (var-get next-withdrawal-id)))
      
      ;; Update consent record
      (map-set user-consents
        { identity-hash: identity-hash, data-requester: data-requester }
        (merge consent-data {
          revoked: true,
          revoked-at: stacks-block-height
        })
      )
      
      ;; Record withdrawal
      (map-set consent-withdrawals
        { withdrawal-id: withdrawal-id }
        {
          identity-hash: identity-hash,
          withdrawn-consent-id: (get consent-id consent-data),
          withdrawal-reason: "User revoked consent",
          withdrawn-by: tx-sender,
          withdrawn-at: stacks-block-height,
          data-deletion-requested: true,
          deletion-completed: false,
          deletion-completed-at: u0
        }
      )
      
      ;; Log the revocation
      (log-access-event identity-hash data-requester "consent-revoked" 
                       "User-initiated consent revocation" "revoked")
      
      (var-set next-withdrawal-id (+ withdrawal-id u1))
      (ok withdrawal-id)
    )
  )
)

;; Set privacy preferences
(define-public (set-privacy-preferences (identity-hash (buff 20)) (consent-duration uint)
                                       (auto-consent-level uint) (data-sharing-restrictions (list 10 (string-ascii 50)))
                                       (notification-preferences (string-ascii 20))
                                       (data-retention-preference uint) (third-party-sharing-allowed bool)
                                       (anonymization-required bool))
  (begin
    (asserts! (is-identity-owner identity-hash tx-sender) err-unauthorized)
    (asserts! (<= auto-consent-level u3) err-invalid-permission)
    (asserts! (<= data-retention-preference (var-get max-data-retention-period)) err-data-retention-violation)
    
    (map-set privacy-preferences
      { identity-hash: identity-hash }
      {
        default-consent-duration: consent-duration,
        auto-consent-level: auto-consent-level,
        data-sharing-restrictions: data-sharing-restrictions,
        notification-preferences: notification-preferences,
        data-retention-preference: data-retention-preference,
        third-party-sharing-allowed: third-party-sharing-allowed,
        anonymization-required: anonymization-required,
        created-at: stacks-block-height,
        updated-at: stacks-block-height
      }
    )
    
    (ok true)
  )
)

;; Grant access permission
(define-public (grant-access-permission (identity-hash (buff 20)) (accessor principal) (data-type (string-ascii 50))
                                       (permission-level uint) (expires-in-blocks uint) (max-usage uint))
  (begin
    (asserts! (is-identity-owner identity-hash tx-sender) err-unauthorized)
    (asserts! (<= permission-level u3) err-invalid-permission)
    (asserts! (is-consent-valid identity-hash accessor) err-consent-expired)
    
    (map-set access-permissions
      { identity-hash: identity-hash, accessor: accessor, data-type: data-type }
      {
        permission-level: permission-level,
        granted-by: tx-sender,
        granted-at: stacks-block-height,
        expires-at: (+ stacks-block-height expires-in-blocks),
        usage-count: u0,
        max-usage: max-usage,
        last-accessed: u0,
        access-conditions: (list)
      }
    )
    
    ;; Log permission grant
    (log-access-event identity-hash accessor "permission-granted" data-type "granted")
    
    (ok true)
  )
)

;; Record data access
(define-public (record-data-access (identity-hash (buff 20)) (data-type (string-ascii 50))
                                  (access-type (string-ascii 20)) (purpose (string-ascii 200)))
  (begin
    (asserts! (is-access-allowed identity-hash tx-sender data-type) err-unauthorized)
    
    ;; Update usage count
    (update-access-usage identity-hash tx-sender data-type)
    
    ;; Log the access
    (log-access-event identity-hash tx-sender access-type purpose "granted")
    
    (ok true)
  )
)

;; Submit data subject request (GDPR-style)
(define-public (submit-data-subject-request (identity-hash (buff 20)) (request-type (string-ascii 50))
                                          (request-data (buff 32)))
  (begin
    (asserts! (is-identity-owner identity-hash tx-sender) err-unauthorized)
    
    (let ((request-id (var-get next-subject-request-id))
          (deadline (+ stacks-block-height u4320))) ;; ~30 days deadline
      
      (map-set data-subject-requests
        { request-id: request-id }
        {
          identity-hash: identity-hash,
          requester: tx-sender,
          request-type: request-type,
          request-data: request-data,
          status: "pending",
          submitted-at: stacks-block-height,
          deadline: deadline,
          processed-at: u0,
          processor: none,
          response-data: none
        }
      )
      
      ;; Log the request
      (log-access-event identity-hash tx-sender "data-request" request-type "submitted")
      
      (var-set next-subject-request-id (+ request-id u1))
      (ok request-id)
    )
  )
)

;; Process data subject request (by authorized processors)
(define-public (process-data-subject-request (request-id uint) (status (string-ascii 20)) 
                                           (response-data (optional (buff 32))))
  (begin
    (asserts! (or (is-eq tx-sender (var-get contract-admin))
                  (is-authorized-data-processor tx-sender)) err-unauthorized)
    
    (let ((request-data (unwrap! (get-data-subject-request request-id) err-not-found)))
      
      (map-set data-subject-requests
        { request-id: request-id }
        (merge request-data {
          status: status,
          processed-at: stacks-block-height,
          processor: (some tx-sender),
          response-data: response-data
        })
      )
      
      ;; Log processing
      (log-access-event (get identity-hash request-data) tx-sender 
                       "request-processed" (get request-type request-data) status)
      
      (ok true)
    )
  )
)

;; Private helper functions

;; Check if caller is identity owner
(define-private (is-identity-owner (identity-hash (buff 20)) (claimed-owner principal))
  ;; This should integrate with identity-registry contract
  ;; For now, simplified implementation
  true ;; TODO: Implement proper identity ownership check
)

;; Check if caller is authorized data processor
(define-private (is-authorized-data-processor (processor principal))
  (match (get-data-processor processor)
    processor-data (get active processor-data)
    false
  )
)

;; Update access usage count
(define-private (update-access-usage (identity-hash (buff 20)) (accessor principal) (data-type (string-ascii 50)))
  (let ((permission-data (unwrap-panic (get-access-permission identity-hash accessor data-type))))
    
    (map-set access-permissions
      { identity-hash: identity-hash, accessor: accessor, data-type: data-type }
      (merge permission-data {
        usage-count: (+ (get usage-count permission-data) u1),
        last-accessed: stacks-block-height
      })
    )
  )
)

;; Log access events
(define-private (log-access-event (identity-hash (buff 20)) (accessor principal) 
                                 (access-type (string-ascii 20)) (purpose (string-ascii 200))
                                 (result (string-ascii 20)))
  (let ((log-id (var-get next-access-log-id)))
    
    (map-set access-audit-log
      { log-id: log-id }
      {
        identity-hash: identity-hash,
        accessor: accessor,
        data-type: (unwrap-panic (as-max-len? purpose u50)), ;; Convert purpose to data-type format
        access-type: access-type,
        purpose: purpose,
        result: result,
        timestamp: stacks-block-height,
        ip-hash: none,
        user-agent-hash: none
      }
    )
    
    (var-set next-access-log-id (+ log-id u1))
  )
)

;; Admin functions

;; Register data processor
(define-public (register-data-processor (processor principal) (processor-name (string-ascii 100))
                                       (processor-type (string-ascii 50)) (data-types (list 20 (string-ascii 50)))
                                       (processing-purposes (list 10 (string-ascii 100)))
                                       (retention-period uint) (security-certification (string-ascii 100))
                                       (privacy-policy-url (string-ascii 200)))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (asserts! (<= retention-period (var-get max-data-retention-period)) err-data-retention-violation)
    
    (map-set data-processors
      { processor: processor }
      {
        processor-name: processor-name,
        processor-type: processor-type,
        data-types: data-types,
        processing-purposes: processing-purposes,
        retention-period: retention-period,
        security-certification: security-certification,
        privacy-policy-url: privacy-policy-url,
        active: true,
        registered-at: stacks-block-height
      }
    )
    
    (ok true)
  )
)

;; Create data retention policy
(define-public (create-data-retention-policy (policy-name (string-ascii 100))
                                           (data-types (list 20 (string-ascii 50)))
                                           (retention-period uint) (deletion-method (string-ascii 50))
                                           (legal-basis (string-ascii 200)))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (asserts! (<= retention-period (var-get max-data-retention-period)) err-data-retention-violation)
    
    (let ((policy-id (var-get next-policy-id)))
      
      (map-set data-retention-policies
        { policy-id: policy-id }
        {
          policy-name: policy-name,
          data-types: data-types,
          retention-period: retention-period,
          deletion-method: deletion-method,
          legal-basis: legal-basis,
          created-by: tx-sender,
          active: true,
          created-at: stacks-block-height
        }
      )
      
      (var-set next-policy-id (+ policy-id u1))
      (ok policy-id)
    )
  )
)

;; Toggle global privacy enforcement
(define-public (toggle-global-privacy)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (var-set global-privacy-enabled (not (var-get global-privacy-enabled)))
    (ok (var-get global-privacy-enabled))
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

