from auth0_login.aws.saml_assertion import AWSSAMLAssertion

saml_response_one_role = 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfZGVlNjY2Zjg2YjA1YWMyZWVjYmQiICBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxOS0wMS0xMlQwOToyNDowM1oiICBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDoxMjIwMC9zYW1sIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+dXJuOm12YW5ob2xzdGVpam4uZXUuYXV0aDAuY29tPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgVmVyc2lvbj0iMi4wIiBJRD0iXzhBbUNLaWxuMnVGQjR2aGxtOXFPT1k3dXA1UE9TYU9MIiBJc3N1ZUluc3RhbnQ9IjIwMTktMDEtMTJUMDk6MjQ6MDMuNzI2WiI+PHNhbWw6SXNzdWVyPnVybjptdmFuaG9sc3RlaWpuLmV1LmF1dGgwLmNvbTwvc2FtbDpJc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PFJlZmVyZW5jZSBVUkk9IiNfOEFtQ0tpbG4ydUZCNHZobG05cU9PWTd1cDVQT1NhT0wiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2VzdFZhbHVlPlFGWlN1MTFPK2tiMkZZdFlrZnZNTTEzcDMydz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+SnJPU0ZYNW5acDVobkVNSXJ3eThSMlVmNnRza0hTSWRHTi84MW41ei9lb2ZWUnEyV2orbG91cVFKd1FEVWlXaFo2cm90N3VoNlF3WGZTSmRsK1hKZjZXSUZPdFVFdlI0NjlFbDArQjZxYjRBZXZiOFpIbTRTUUliLzZGV1d5cDhpZFZUWlMvdEVzRSs1eGJnZ3g4cUxjZkJiVGJFS0JvSElDS0NrSDNUTTl6WVVaSVllb3VQeC9hbkh3QWVCVjNhc2VWckhRVWlFMjVGTkc1ODU2dU5VM2MrQVZpcWg1T0JNdmlxM2R5RjFGR01ydlhpWFdzYWVkSEh3dW5WclNGcTNIeEU2NVdBd1lneU90U1JWVExBTDJEdjg1QmdYM2FUeFhud1Jjck4xWGtIa2xNMVdRY3ZpSWM0clg2a1UzQnF2eDNqaS92cENxZno5eHJrN1JxQUNBPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUNzakNDQVpxZ0F3SUJBZ0lKYXFXRU0rV1dYeEZKTUEwR0NTcUdTSWIzRFFFQkJRVUFNQUF3SGhjTk1UWXdNVEEwTVRRek5qUTNXaGNOTWprd09URXlNVFF6TmpRM1dqQUFNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRQYkl2U3NsaUNHVlMzZysrS2NYd3pBQVRCdEhUNVlOMWJVYmlzVzduMTZSaTBJelhMV0N5ZUdkRXR2ek1yNzhhQ1FRNUlmUngxTEdKYzN4NEpURlJKWTV4NXZwUXJrVWZtcFZkbHkzc1BtcEQ0b280UTZxUXk4V0RPbXNrcGxIUmV2YmtWajZRWEZwNTcxSnBOeXpxNitzMjJLanAwMWJ0QTE3T2hKRUJyckZsSVlaSURmSC96bTRFRUFCTDVVQlNwWENKRWpreEJrWGJtUFJieXlmR1d4WDR2RFZORmFyN0o4UGRPZzREN1d2aHVudWc4bVdlTUlIdXJzK1p6d0VjL0NXMXlxRTJkL0o5U0c3akpENWRYTGVLWmVhc2p0UEREYkhxb05jNHFrOWtmYzJwV2lQQnlZRy8xd3gzUVhZLzBvZjBFTlV2cWczbExjVFNtWWV0d0lEQVFBQm95OHdMVEFNQmdOVkhSTUVCVEFEQVFIL01CMEdBMVVkRGdRV0JCU0hram1DeHloWEVuNElaWDhQbHRhb1p0TjVWVEFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBRDliY08rWVl6OGJsdWY2a3gzazNNc25zYkQ1VmF0MlE0OWw0Nm1kTUkrZ2ZxSTlRMGlIT1NWTHdZb1BPSHFPMmEzd3VOVnl6NWtUc0FKZlBXYVpwdWlUWnQrYmtwNFpVUVU1YnNkdE5RZlpPdkloSThzSXZJK2JZS0dnVTNRNERIMkhzbHViSDNXcncwN3JGSElic1JsZjJlT2hQZ0g0RTljT09OTmdpdndDeVQ1WWxOQWJrNVpkUnZGdnRpZ1g1TzN2b01pVlpmVStCK1JQUE1lN293WUlib0RFUHk5bXVyZG9hRjJHbm9QM1RNRHRrQXNkYmQvRHZzSHRIeUtPZlNXVHI2THM3eDN3V0o2K1Q3WU8rcXB5TW01Z3VmZk9mWDRrYWh5aTJha09kSWI4MDZDYlorV0duS1JzU3Z4MHU5UHMzUGtOTnhqVkRjTkpxbWVYV2dRPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5hdXRoMHw1YzM3NTVkYmQ4NzAxYzM2MThjZmY2NjQ8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTktMDEtMTJUMTA6MjQ6MDMuNzI2WiIgUmVjaXBpZW50PSJodHRwczovL3NpZ25pbi5hd3MuYW1hem9uLmNvbS9zYW1sIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTktMDEtMTJUMDk6MjQ6MDMuNzI2WiIgTm90T25PckFmdGVyPSIyMDE5LTAxLTEyVDEwOjI0OjAzLjcyNloiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTktMDEtMTJUMDk6MjQ6MDMuNzI2WiIgU2Vzc2lvbkluZGV4PSJfVkFDWTNNZjlDU0Uwa3ZmZkcycHNFRkVRNnJCdmlhdEoiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3Nlczp1bnNwZWNpZmllZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyNDUxMTE2MTIyMTQ6cm9sZS9PQXV0aEFkbWluaXN0cmF0b3IsYXJuOmF3czppYW06OjI0NTExMTYxMjIxNDpzYW1sLXByb3ZpZGVyL2F1dGgwLW12YW5ob2xzdGVpam4tZXUtYXV0aDAtY29tLXByb3ZpZGVyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1JvbGVTZXNzaW9uTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFkbWluPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3VwbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hcmtAYmlueC5pbzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vaWRlbnRpdGllcy9kZWZhdWx0L3VzZXJfaWQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj41YzM3NTVkYmQ4NzAxYzM2MThjZmY2NjQ8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2lkZW50aXRpZXMvZGVmYXVsdC9wcm92aWRlciIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmF1dGgwPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9pZGVudGl0aWVzL2RlZmF1bHQvY29ubmVjdGlvbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlVzZXJuYW1lLVBhc3N3b3JkLUF1dGhlbnRpY2F0aW9uPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9pZGVudGl0aWVzL2RlZmF1bHQvaXNTb2NpYWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6Ym9vbGVhbiI+ZmFsc2U8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2VtYWlsIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+bWFya0BiaW54LmlvPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9waWN0dXJlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+aHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvZTI1MTgyZGQ0YzU4YjZjZGViOWY2ZTRhOWE4OWUwMDU/cz00ODAmYW1wO3I9cGcmYW1wO2Q9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRm1hLnBuZzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vbmlja25hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYXJrPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9uYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+bWFya0BiaW54LmlvPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9sYXN0X3Bhc3N3b3JkX3Jlc2V0IiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+MjAxOS0wMS0xMlQwOToyMDozMC40NjZaPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9lbWFpbF92ZXJpZmllZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpib29sZWFuIj50cnVlPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9jbGllbnRJRCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPktNem52aDNCd0R0bkoyT25SaUFVR05KY1pxRXJoY0d1PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS91cGRhdGVkX2F0IiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOmFueVR5cGUiPlNhdCBKYW4gMTIgMjAxOSAwOToyNDowMSBHTVQrMDAwMCAoVVRDKTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vdXNlcl9pZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmF1dGgwfDVjMzc1NWRiZDg3MDFjMzYxOGNmZjY2NDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vY3JlYXRlZF9hdCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5UaHUgSmFuIDEwIDIwMTkgMTQ6MjU6MzEgR01UKzAwMDAgKFVUQyk8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4='
saml_response_two_roles = 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfMWU1YjBjZDcxNWQyZGU2MmE3NWUiICBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxOS0wMS0xNVQxMjoyODoxMFoiICBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDoxMjIwMC9zYW1sIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+dXJuOm12YW5ob2xzdGVpam4uZXUuYXV0aDAuY29tPC9zYW1sOklzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgVmVyc2lvbj0iMi4wIiBJRD0iX0pWZ2tOWm5MbXl5dTV4RG5OVHRvaFFndFpGTnpaMnZnIiBJc3N1ZUluc3RhbnQ9IjIwMTktMDEtMTVUMTI6Mjg6MDkuOTk3WiI+PHNhbWw6SXNzdWVyPnVybjptdmFuaG9sc3RlaWpuLmV1LmF1dGgwLmNvbTwvc2FtbDpJc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PFJlZmVyZW5jZSBVUkk9IiNfSlZna05abkxteXl1NXhEbk5UdG9oUWd0WkZOeloydmciPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2VzdFZhbHVlPkI3dG1YZ2hidktsTm9iQUVybDhJcDdvSjlXZz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+b09mV3FmcGRHQk1RTjRNcTVDY3Y5eVpKQ1lHeTZGM1hNT2pQVTg5Z3kxeHdkbFl3dks4c1FSQlBvaHh4NGZxZklycThiSGtEaWxpaWR2Sm9FcGFTRzA4U1BRcExLVTAzNWVEN3JWbmhsYS9NWnljMEUwZEJlUzJEbFNHOTlZeEFnTUVkTCtKSm0xSGtaQ3k4YUFxaGlJOG1QOEdGV1VLRHFqNWEra2FHTm9uUUIrOUxzcjJsZXBya2d4L3l3RnJsLzB6WmEra1F2QWp2WUUrMW1CUG8wRWZjbFRRSTlaUlBMcW9seW5TWENEcmVwb3N5UFhoREwyKzVPQis2d1crVE5mdzJ6VUhYRjc5MXY1UytLcElwNDZHUTlnWjc3RlpDYWVzRzVZeVlrSWNqTHQvYVNoZEQ3VHROeE9GRFdUNTdQMHljN1k5enpxZGFEZmxkbDY3cVZnPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUNzakNDQVpxZ0F3SUJBZ0lKYXFXRU0rV1dYeEZKTUEwR0NTcUdTSWIzRFFFQkJRVUFNQUF3SGhjTk1UWXdNVEEwTVRRek5qUTNXaGNOTWprd09URXlNVFF6TmpRM1dqQUFNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRQYkl2U3NsaUNHVlMzZysrS2NYd3pBQVRCdEhUNVlOMWJVYmlzVzduMTZSaTBJelhMV0N5ZUdkRXR2ek1yNzhhQ1FRNUlmUngxTEdKYzN4NEpURlJKWTV4NXZwUXJrVWZtcFZkbHkzc1BtcEQ0b280UTZxUXk4V0RPbXNrcGxIUmV2YmtWajZRWEZwNTcxSnBOeXpxNitzMjJLanAwMWJ0QTE3T2hKRUJyckZsSVlaSURmSC96bTRFRUFCTDVVQlNwWENKRWpreEJrWGJtUFJieXlmR1d4WDR2RFZORmFyN0o4UGRPZzREN1d2aHVudWc4bVdlTUlIdXJzK1p6d0VjL0NXMXlxRTJkL0o5U0c3akpENWRYTGVLWmVhc2p0UEREYkhxb05jNHFrOWtmYzJwV2lQQnlZRy8xd3gzUVhZLzBvZjBFTlV2cWczbExjVFNtWWV0d0lEQVFBQm95OHdMVEFNQmdOVkhSTUVCVEFEQVFIL01CMEdBMVVkRGdRV0JCU0hram1DeHloWEVuNElaWDhQbHRhb1p0TjVWVEFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBRDliY08rWVl6OGJsdWY2a3gzazNNc25zYkQ1VmF0MlE0OWw0Nm1kTUkrZ2ZxSTlRMGlIT1NWTHdZb1BPSHFPMmEzd3VOVnl6NWtUc0FKZlBXYVpwdWlUWnQrYmtwNFpVUVU1YnNkdE5RZlpPdkloSThzSXZJK2JZS0dnVTNRNERIMkhzbHViSDNXcncwN3JGSElic1JsZjJlT2hQZ0g0RTljT09OTmdpdndDeVQ1WWxOQWJrNVpkUnZGdnRpZ1g1TzN2b01pVlpmVStCK1JQUE1lN293WUlib0RFUHk5bXVyZG9hRjJHbm9QM1RNRHRrQXNkYmQvRHZzSHRIeUtPZlNXVHI2THM3eDN3V0o2K1Q3WU8rcXB5TW01Z3VmZk9mWDRrYWh5aTJha09kSWI4MDZDYlorV0duS1JzU3Z4MHU5UHMzUGtOTnhqVkRjTkpxbWVYV2dRPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5hdXRoMHw1YzM3NTVkYmQ4NzAxYzM2MThjZmY2NjQ8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTktMDEtMTVUMTM6Mjg6MDkuOTk3WiIgUmVjaXBpZW50PSJodHRwczovL3NpZ25pbi5hd3MuYW1hem9uLmNvbS9zYW1sIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTktMDEtMTVUMTI6Mjg6MDkuOTk3WiIgTm90T25PckFmdGVyPSIyMDE5LTAxLTE1VDEzOjI4OjA5Ljk5N1oiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTktMDEtMTVUMTI6Mjg6MDkuOTk3WiIgU2Vzc2lvbkluZGV4PSJfcGJFUWphTnZpLXJhTnVjS0lJdjhBVkxFTVEyejhSamUiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3Nlczp1bnNwZWNpZmllZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyNDUxMTE2MTIyMTQ6cm9sZS9PQXV0aEFkbWluaXN0cmF0b3IsYXJuOmF3czppYW06OjI0NTExMTYxMjIxNDpzYW1sLXByb3ZpZGVyL2F1dGgwLW12YW5ob2xzdGVpam4tZXUtYXV0aDAtY29tLXByb3ZpZGVyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFybjphd3M6aWFtOjoyNDUxMTE2MTIyMTQ6cm9sZS9PQXV0aElkZW50aXR5LGFybjphd3M6aWFtOjoyNDUxMTE2MTIyMTQ6c2FtbC1wcm92aWRlci9hdXRoMC1tdmFuaG9sc3RlaWpuLWV1LWF1dGgwLWNvbS1wcm92aWRlcjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYXJrQGJpbnguaW88L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvdXBuIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+bWFya0BiaW54LmlvPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9pZGVudGl0aWVzL2RlZmF1bHQvdXNlcl9pZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjVjMzc1NWRiZDg3MDFjMzYxOGNmZjY2NDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vaWRlbnRpdGllcy9kZWZhdWx0L3Byb3ZpZGVyIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+YXV0aDA8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2lkZW50aXRpZXMvZGVmYXVsdC9jb25uZWN0aW9uIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+VXNlcm5hbWUtUGFzc3dvcmQtQXV0aGVudGljYXRpb248L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2lkZW50aXRpZXMvZGVmYXVsdC9pc1NvY2lhbCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpib29sZWFuIj5mYWxzZTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5hdXRoMC5jb20vZW1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYXJrQGJpbnguaW88L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL3BpY3R1cmUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5odHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci9lMjUxODJkZDRjNThiNmNkZWI5ZjZlNGE5YTg5ZTAwNT9zPTQ4MCZhbXA7cj1wZyZhbXA7ZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGbWEucG5nPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9uaWNrbmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hcms8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL25hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYXJrQGJpbnguaW88L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2xhc3RfcGFzc3dvcmRfcmVzZXQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4yMDE5LTAxLTEyVDA5OjIwOjMwLjQ2Nlo8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2VtYWlsX3ZlcmlmaWVkIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOmJvb2xlYW4iPnRydWU8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL2NsaWVudElEIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+S016bnZoM0J3RHRuSjJPblJpQVVHTkpjWnFFcmhjR3U8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMuYXV0aDAuY29tL3VwZGF0ZWRfYXQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6YW55VHlwZSI+VHVlIEphbiAxNSAyMDE5IDEyOjI4OjA4IEdNVCswMDAwIChVVEMpPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS91c2VyX2lkIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+YXV0aDB8NWMzNzU1ZGJkODcwMWMzNjE4Y2ZmNjY0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLmF1dGgwLmNvbS9jcmVhdGVkX2F0IiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOmFueVR5cGUiPlRodSBKYW4gMTAgMjAxOSAxNDoyNTozMSBHTVQrMDAwMCAoVVRDKTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg=='


def test_parse():
    command = AWSSAMLAssertion(saml_response_one_role)
    assert len(command.roles) == 1

    command = AWSSAMLAssertion(saml_response_two_roles)
    assert len(command.roles) == 2


if __name__ == '__main__':
    test_parse()
