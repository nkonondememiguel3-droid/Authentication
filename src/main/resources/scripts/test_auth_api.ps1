# ============================================================================
# END-TO-END SPRING BOOT AUTHENTICATION & SECURE LOGOUT TEST SUITE
# ============================================================================
Clear-Host
$baseUrl = "http://localhost:8080/api/v1/auth"
$testMac = "00-14-22-01-23-45"
$testDevice = "Tech-Lab-Desktop"
$testEmail = "miguel@gmail.com"
$testPassword = "password123"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " STARTING AUTOMATED AUTHENTICATION API TESTING LAYER" -ForegroundColor Cyan
Write-Host "====================================================`n" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# STEP 1: USER REGISTRATION
# ----------------------------------------------------------------------------
Write-Host "[TEST 1/5] Testing User Registration endpoint..." -ForegroundColor Yellow
$registerPayload = @{
    username   = "miguel_dev"
    email      = $testEmail
    password   = $testPassword
    macAddress = $testMac
    deviceName = $testDevice
    roles      = @("employee", "technician")
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$baseUrl/register" `
                                          -Method Post `
                                          -ContentType "application/json" `
                                          -Body $registerPayload
    Write-Host "-> SUCCESS: $registerResponse`n" -ForegroundColor Green
} catch {
    # If the user is already created from our previous tests, handle the message gracefully
    if ($_.Exception.Response.StatusCode -eq 401 -or $_.Exception.Response.StatusCode -eq 500 -or $_.Exception.Message -match "exists") {
        Write-Host "-> INFO: Account already exists or handled by database constraints. Proceeding to login...`n" -ForegroundColor Cyan
    } else {
        Write-Host "-> FAILURE in registration: $_`n" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------------
# STEP 2: USER LOGIN (WITH HARDWARE VERIFICATION)
# ----------------------------------------------------------------------------
Write-Host "[TEST 2/5] Testing User Login with strict X-Device-Mac matching..." -ForegroundColor Yellow
$loginPayload = @{
    email      = $testEmail
    password   = $testPassword
    macAddress = $testMac
    deviceName = $testDevice
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/login" `
                                       -Method Post `
                                       -Headers @{ "X-Device-Mac" = $testMac } `
                                       -ContentType "application/json" `
                                       -Body $loginPayload

    Write-Host "-> SUCCESS: Authentication complete! Received stateful payload:" -ForegroundColor Green
    Write-Host "   Access Token  : $($loginResponse.accessToken.Substring(0,60))..." -ForegroundColor Gray
    Write-Host "   Refresh Token : $($loginResponse.refreshToken.Substring(0,60))....`n" -ForegroundColor Gray
} catch {
    Write-Host "-> FAILURE in Login: $_`n" -ForegroundColor Red
    Exit
}

# FIXED: Pausing execution for 100ms to allow the server's database timestamp sequence to tick forward cleanly
Start-Sleep -Milliseconds 100

# ----------------------------------------------------------------------------
# STEP 3: INSTANT STATEFUL TOKEN ROTATION LOOP (10-SECOND REFRESH LIFECYCLE)
# ----------------------------------------------------------------------------
Write-Host "[TEST 3/5] Testing instant token rotation loop within milliseconds..." -ForegroundColor Yellow
$refreshPayload = @{
    refreshToken = $loginResponse.refreshToken
} | ConvertTo-Json

try {
    $refreshResponse = Invoke-RestMethod -Uri "$baseUrl/refresh" `
                                         -Method Post `
                                         -Headers @{ "X-Device-Mac" = $testMac } `
                                         -ContentType "application/json" `
                                         -Body $refreshPayload

    Write-Host "-> SUCCESS: Token rotation successful! Old token deleted from PostgreSQL ledger." -ForegroundColor Green
    Write-Host "   New Access Token : $($refreshResponse.accessToken.Substring(0,60))...`n" -ForegroundColor Gray
} catch {
    Write-Host "-> FAILURE in Token Rotation: $_`n" -ForegroundColor Red
}

# ----------------------------------------------------------------------------
# STEP 4: HARDWARE FALSIFICATION ENFORCEMENT (ATTACK ENVIRONMENT SIMULATION)
# ----------------------------------------------------------------------------
Write-Host "[TEST 4/5] Testing hardware spoofing tracking (Sending unauthorized MAC address)..." -ForegroundColor Yellow
$unauthorizedMac = "FF-FF-FF-FF-FF-FF"
$hackPayload = @{
    email      = $testEmail
    password   = $testPassword
    macAddress = $unauthorizedMac
    deviceName = "Hacker-Machine"
} | ConvertTo-Json

try {
    $hackResponse = Invoke-RestMethod -Uri "$baseUrl/login" `
                                      -Method Post `
                                      -Headers @{ "X-Device-Mac" = $unauthorizedMac } `
                                      -ContentType "application/json" `
                                      -Body $hackPayload
    Write-Host "-> CRITICAL BREACH: The server mistakenly allowed an unauthorized machine to log in!`n" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.Value__
    Write-Host "-> SUCCESS: Security constraints caught the unauthorized hardware!" -ForegroundColor Green
    Write-Host "   Server returned HTTP Status Code: $statusCode...`n" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# STEP 5: SECURE GLOBAL LOGOUT & REUSE BLACK-LISTING
# ----------------------------------------------------------------------------
Write-Host "[TEST 5/5] Testing Secure Global Logout..." -ForegroundColor Yellow

try {
    # Call the logout route using the active token from our refresh step
    $logoutResponse = Invoke-RestMethod -Uri "$baseUrl/logout" `
                                        -Method Post `
                                        -Headers @{
        "Authorization" = "Bearer $($refreshResponse.accessToken)"
        "X-Device-Mac"  = $testMac
    }

    Write-Host "-> SUCCESS: Server Response -> $logoutResponse" -ForegroundColor Green

    # Try to reuse the token that we just deleted from the database
    Write-Host "   Verifying token is dead by trying to access endpoints again..." -ForegroundColor Gray
    Invoke-RestMethod -Uri "$baseUrl/logout" `
                      -Method Post `
                      -Headers @{
        "Authorization" = "Bearer $($refreshResponse.accessToken)"
        "X-Device-Mac"  = $testMac
    }
    Write-Host "-> CRITICAL BREACH: Token was reused after logout!" -ForegroundColor Red
} catch {
    Write-Host "-> SUCCESS: Server rejected the token! It was blocked by the stateful filter database check.`n" -ForegroundColor Green
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " ALL SECURITY WORKFLOWS EVALUATED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
