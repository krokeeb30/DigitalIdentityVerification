;; Verification Oracle Contract
;; Handles identity verification requests from third parties
;; Manages verification workflows, approval processes, and external integrations

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u200))
(define-constant err-not-found (err u201))
(define-constant err-already-exists (err u202))
(define-constant err-invalid-request (err u203))
(define-constant err-unauthorized (err u204))
(define-constant err-request-expired (err u205))
(define-constant err-invalid-status (err u206))
(define-constant err-insufficient-verification (err u207))
(define-constant err-rate-limited (err u208))

;; Data Variables
(define-data-var contract-admin principal tx-sender)
(define-data-var oracle-active bool true)
(define-data-var next-request-id uint u1)
(define-data-var next-response-id uint u1)
(define-data-var verification-fee uint u1000) ;; Base fee in microSTX
(define-data-var max-requests-per-hour uint u100)

;; Data Maps
;; Verification requests from third parties
(define-map verification-requests
  { request-id: uint }
  {
    identity-hash: (buff 20),
    requester: principal,
    requester-type: (string-ascii 50), ;; financial-institution, government, employer, etc.
    verification-level: uint, ;; 1=basic, 2=enhanced, 3=premium
    verification-scope: (list 10 (string-ascii 50)), ;; What to verify: age, citizenship, address, etc.
    request-data: (buff 32), ;; Hash of additional request parameters
    priority: uint, ;; 1=low, 2=normal, 3=high, 4=urgent
    status: (string-ascii 20), ;; pending, processing, completed, rejected, expired
    requested-at: uint,
    expires-at: uint,
    fee-paid: uint,
    callback-url: (optional (string-ascii 200))
  }
)

;; Verification responses
(define-map verification-responses
  { response-id: uint }
  {
    request-id: uint,
    identity-hash: (buff 20),
    verification-result: (string-ascii 20), ;; verified, partial, failed, expired
    confidence-score: uint, ;; 0-100 confidence in verification
    verified-attributes: (list 20 (string-ascii 50)), ;; Which attributes were successfully verified
    response-data: (buff 32), ;; Hash of detailed response data
    verifier: principal,
    verified-at: uint,
    expires-at: uint
  }
)

;; Authorized verifiers (who can process verification requests)
(define-map authorized-verifiers
  { verifier: principal }
  {
    organization-name: (string-ascii 100),
    verification-types: (list 10 (string-ascii 50)),
    max-verification-level: uint,
    active: bool,
    reputation-score: uint, ;; 0-100
    total-verifications: uint,
    successful-verifications: uint,
    registered-at: uint
  }
)

;; Requester profiles and rate limiting
(define-map requester-profiles
  { requester: principal }
  {
    organization-name: (string-ascii 100),
    requester-type: (string-ascii 50),
    tier: uint, ;; 1=basic, 2=premium, 3=enterprise
    rate-limit: uint, ;; Requests per hour
    total-requests: uint,
    successful-requests: uint,
    registered-at: uint,
    last-request-time: uint
  }
)

;; Rate limiting tracking
(define-map rate-limits
  { requester: principal, hour: uint }
  {
    request-count: uint
  }
)

;; Verification templates (predefined verification workflows)
(define-map verification-templates
  { template-id: uint }
  {
    template-name: (string-ascii 100),
    required-attributes: (list 20 (string-ascii 50)),
    minimum-verification-level: uint,
    estimated-time: uint, ;; in blocks
    base-fee: uint,
    active: bool,
    created-by: principal,
    created-at: uint
  }
)

(define-data-var next-template-id uint u1)

;; External data source integrations
(define-map data-sources
  { source-id: uint }
  {
    source-name: (string-ascii 100),
    source-type: (string-ascii 50), ;; government, credit-bureau, employer, etc.
    api-endpoint: (string-ascii 200),
    supported-attributes: (list 20 (string-ascii 50)),
    reliability-score: uint, ;; 0-100
    response-time: uint, ;; average response time in blocks
    active: bool
  }
)

(define-data-var next-source-id uint u1)

;; Verification workflow states
(define-map workflow-states
  { request-id: uint, step: uint }
  {
    step-name: (string-ascii 50),
    status: (string-ascii 20),
    started-at: uint,
    completed-at: uint,
    processor: (optional principal),
    step-data: (buff 32)
  }
)

;; Read-only functions

;; Get verification request
(define-read-only (get-verification-request (request-id uint))
  (map-get? verification-requests { request-id: request-id })
)

;; Get verification response
(define-read-only (get-verification-response (response-id uint))
  (map-get? verification-responses { response-id: response-id })
)

;; Check if verifier is authorized
(define-read-only (is-authorized-verifier (verifier principal))
  (match (map-get? authorized-verifiers { verifier: verifier })
    verifier-data (get active verifier-data)
    false
  )
)

;; Get requester profile
(define-read-only (get-requester-profile (requester principal))
  (map-get? requester-profiles { requester: requester })
)

;; Check rate limit
(define-read-only (check-rate-limit (requester principal))
  (let ((current-hour (/ stacks-block-height u144)) ;; Approximate blocks per hour
        (profile (map-get? requester-profiles { requester: requester })))
    
    (match profile
      profile-data
      (let ((rate-data (map-get? rate-limits { requester: requester, hour: current-hour })))
        (match rate-data
          limits (< (get request-count limits) (get rate-limit profile-data))
          true
        )
      )
      false
    )
  )
)

;; Get verification template
(define-read-only (get-verification-template (template-id uint))
  (map-get? verification-templates { template-id: template-id })
)

;; Get data source
(define-read-only (get-data-source (source-id uint))
  (map-get? data-sources { source-id: source-id })
)

;; Get workflow state
(define-read-only (get-workflow-state (request-id uint) (step uint))
  (map-get? workflow-states { request-id: request-id, step: step })
)

;; Calculate verification fee
(define-read-only (calculate-verification-fee (verification-level uint) (scope-count uint))
  (let ((base-fee (var-get verification-fee))
        (level-multiplier (+ verification-level u1))
        (scope-multiplier (if (> scope-count u0) scope-count u1)))
    (ok (* (* base-fee level-multiplier) scope-multiplier))
  )
)

;; Check oracle status
(define-read-only (is-oracle-active)
  (var-get oracle-active)
)

;; Public functions

;; Submit verification request
(define-public (submit-verification-request (identity-hash (buff 20)) (requester-type (string-ascii 50))
                                          (verification-level uint) (verification-scope (list 10 (string-ascii 50)))
                                          (priority uint) (expires-in-blocks uint)
                                          (callback-url (optional (string-ascii 200))))
  (begin
    (asserts! (var-get oracle-active) (err u209))
    (asserts! (check-rate-limit tx-sender) err-rate-limited)
    (asserts! (<= verification-level u3) err-invalid-request)
    (asserts! (and (>= priority u1) (<= priority u4)) err-invalid-request)
    
    (let ((request-id (var-get next-request-id))
          (scope-count (len verification-scope))
          (fee (unwrap! (calculate-verification-fee verification-level scope-count) err-invalid-request))
          (expires-at (+ stacks-block-height expires-in-blocks)))
      
      ;; Create verification request
      (map-set verification-requests
        { request-id: request-id }
        {
          identity-hash: identity-hash,
          requester: tx-sender,
          requester-type: requester-type,
          verification-level: verification-level,
          verification-scope: verification-scope,
          request-data: (hash160 (concat identity-hash (unwrap-panic (to-consensus-buff? request-id)))),
          priority: priority,
          status: "pending",
          requested-at: stacks-block-height,
          expires-at: expires-at,
          fee-paid: fee,
          callback-url: callback-url
        }
      )
      
      ;; Update rate limiting
      (update-rate-limit tx-sender)
      
      ;; Initialize workflow
      (initialize-verification-workflow request-id)
      
      (var-set next-request-id (+ request-id u1))
      (ok request-id)
    )
  )
)

;; Process verification request (by authorized verifiers)
(define-public (process-verification-request (request-id uint))
  (begin
    (asserts! (is-authorized-verifier tx-sender) err-unauthorized)
    
    (let ((request-data (unwrap! (get-verification-request request-id) err-not-found)))
      
      (asserts! (is-eq (get status request-data) "pending") err-invalid-status)
      (asserts! (< stacks-block-height (get expires-at request-data)) err-request-expired)
      
      ;; Update request status
      (map-set verification-requests
        { request-id: request-id }
        (merge request-data { status: "processing" })
      )
      
      ;; Update workflow state
      (update-workflow-step request-id u1 "processing" tx-sender)
      
      (ok true)
    )
  )
)

;; Submit verification response
(define-public (submit-verification-response (request-id uint) (verification-result (string-ascii 20))
                                           (confidence-score uint) (verified-attributes (list 20 (string-ascii 50)))
                                           (response-data (buff 32)) (expires-in-blocks uint))
  (begin
    (asserts! (is-authorized-verifier tx-sender) err-unauthorized)
    (asserts! (<= confidence-score u100) err-invalid-request)
    
    (let ((request-data (unwrap! (get-verification-request request-id) err-not-found))
          (response-id (var-get next-response-id)))
      
      (asserts! (is-eq (get status request-data) "processing") err-invalid-status)
      
      ;; Create verification response
      (map-set verification-responses
        { response-id: response-id }
        {
          request-id: request-id,
          identity-hash: (get identity-hash request-data),
          verification-result: verification-result,
          confidence-score: confidence-score,
          verified-attributes: verified-attributes,
          response-data: response-data,
          verifier: tx-sender,
          verified-at: stacks-block-height,
          expires-at: (+ stacks-block-height expires-in-blocks)
        }
      )
      
      ;; Update request status
      (map-set verification-requests
        { request-id: request-id }
        (merge request-data { status: "completed" })
      )
      
      ;; Update verifier statistics
      (update-verifier-stats tx-sender verification-result)
      
      ;; Complete workflow
      (update-workflow-step request-id u2 "completed" tx-sender)
      
      (var-set next-response-id (+ response-id u1))
      (ok response-id)
    )
  )
)

;; Create verification template
(define-public (create-verification-template (template-name (string-ascii 100))
                                           (required-attributes (list 20 (string-ascii 50)))
                                           (minimum-verification-level uint) (estimated-time uint)
                                           (base-fee uint))
  (begin
    (asserts! (is-authorized-verifier tx-sender) err-unauthorized)
    
    (let ((template-id (var-get next-template-id)))
      
      (map-set verification-templates
        { template-id: template-id }
        {
          template-name: template-name,
          required-attributes: required-attributes,
          minimum-verification-level: minimum-verification-level,
          estimated-time: estimated-time,
          base-fee: base-fee,
          active: true,
          created-by: tx-sender,
          created-at: stacks-block-height
        }
      )
      
      (var-set next-template-id (+ template-id u1))
      (ok template-id)
    )
  )
)

;; Register requester
(define-public (register-requester (organization-name (string-ascii 100)) (requester-type (string-ascii 50))
                                  (tier uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (asserts! (<= tier u3) err-invalid-request)
    
    (let ((rate-limit (get-tier-rate-limit tier)))
      
      (map-set requester-profiles
        { requester: tx-sender }
        {
          organization-name: organization-name,
          requester-type: requester-type,
          tier: tier,
          rate-limit: rate-limit,
          total-requests: u0,
          successful-requests: u0,
          registered-at: stacks-block-height,
          last-request-time: u0
        }
      )
      
      (ok true)
    )
  )
)

;; Cancel verification request
(define-public (cancel-verification-request (request-id uint))
  (begin
    (let ((request-data (unwrap! (get-verification-request request-id) err-not-found)))
      
      (asserts! (is-eq (get requester request-data) tx-sender) err-unauthorized)
      (asserts! (not (is-eq (get status request-data) "completed")) err-invalid-status)
      
      (map-set verification-requests
        { request-id: request-id }
        (merge request-data { status: "cancelled" })
      )
      
      ;; Update workflow
      (update-workflow-step request-id u99 "cancelled" tx-sender)
      
      (ok true)
    )
  )
)

;; Private helper functions

;; Update rate limiting
(define-private (update-rate-limit (requester principal))
  (let ((current-hour (/ stacks-block-height u144))
        (current-count (get-current-request-count requester current-hour)))
    
    (map-set rate-limits
      { requester: requester, hour: current-hour }
      { request-count: (+ current-count u1) }
    )
    
    ;; Update requester profile
    (update-requester-stats requester)
  )
)

;; Get current request count for rate limiting
(define-private (get-current-request-count (requester principal) (hour uint))
  (match (map-get? rate-limits { requester: requester, hour: hour })
    rate-data (get request-count rate-data)
    u0
  )
)

;; Update requester statistics
(define-private (update-requester-stats (requester principal))
  (let ((profile-data (unwrap-panic (get-requester-profile requester))))
    
    (map-set requester-profiles
      { requester: requester }
      (merge profile-data {
        total-requests: (+ (get total-requests profile-data) u1),
        last-request-time: stacks-block-height
      })
    )
  )
)

;; Update verifier statistics
(define-private (update-verifier-stats (verifier principal) (result (string-ascii 20)))
  (let ((verifier-data (unwrap-panic (map-get? authorized-verifiers { verifier: verifier })))
        (is-successful (is-eq result "verified")))
    
    (map-set authorized-verifiers
      { verifier: verifier }
      (merge verifier-data {
        total-verifications: (+ (get total-verifications verifier-data) u1),
        successful-verifications: (if is-successful
                                     (+ (get successful-verifications verifier-data) u1)
                                     (get successful-verifications verifier-data))
      })
    )
  )
)

;; Initialize verification workflow
(define-private (initialize-verification-workflow (request-id uint))
  (map-set workflow-states
    { request-id: request-id, step: u0 }
    {
      step-name: "submitted",
      status: "completed",
      started-at: stacks-block-height,
      completed-at: stacks-block-height,
      processor: (some tx-sender),
      step-data: 0x00
    }
  )
)

;; Update workflow step
(define-private (update-workflow-step (request-id uint) (step uint) (status (string-ascii 20)) 
                                     (processor principal))
  (map-set workflow-states
    { request-id: request-id, step: step }
    {
      step-name: (get-step-name step),
      status: status,
      started-at: stacks-block-height,
      completed-at: (if (is-eq status "completed") stacks-block-height u0),
      processor: (some processor),
      step-data: 0x00
    }
  )
)

;; Get step name by step number
(define-private (get-step-name (step uint))
  (if (is-eq step u0)
    "submitted"
    (if (is-eq step u1)
      "processing"
      (if (is-eq step u2)
        "completed"
        "unknown"
      )
    )
  )
)

;; Get rate limit by tier
(define-private (get-tier-rate-limit (tier uint))
  (if (is-eq tier u1)
    u10   ;; Basic: 10 requests per hour
    (if (is-eq tier u2)
      u50   ;; Premium: 50 requests per hour
      u200  ;; Enterprise: 200 requests per hour
    )
  )
)

;; Admin functions

;; Register authorized verifier
(define-public (register-authorized-verifier (verifier principal) (organization-name (string-ascii 100))
                                           (verification-types (list 10 (string-ascii 50)))
                                           (max-verification-level uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (asserts! (<= max-verification-level u3) err-invalid-request)
    
    (map-set authorized-verifiers
      { verifier: verifier }
      {
        organization-name: organization-name,
        verification-types: verification-types,
        max-verification-level: max-verification-level,
        active: true,
        reputation-score: u100,
        total-verifications: u0,
        successful-verifications: u0,
        registered-at: stacks-block-height
      }
    )
    
    (ok true)
  )
)

;; Register data source
(define-public (register-data-source (source-name (string-ascii 100)) (source-type (string-ascii 50))
                                    (api-endpoint (string-ascii 200))
                                    (supported-attributes (list 20 (string-ascii 50))))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    
    (let ((source-id (var-get next-source-id)))
      
      (map-set data-sources
        { source-id: source-id }
        {
          source-name: source-name,
          source-type: source-type,
          api-endpoint: api-endpoint,
          supported-attributes: supported-attributes,
          reliability-score: u100,
          response-time: u10,
          active: true
        }
      )
      
      (var-set next-source-id (+ source-id u1))
      (ok source-id)
    )
  )
)

;; Toggle oracle status
(define-public (toggle-oracle-status)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (var-set oracle-active (not (var-get oracle-active)))
    (ok (var-get oracle-active))
  )
)

;; Update verification fee
(define-public (update-verification-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-admin)) err-owner-only)
    (var-set verification-fee new-fee)
    (ok new-fee)
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

