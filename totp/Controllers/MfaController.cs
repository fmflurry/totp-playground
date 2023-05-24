using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using OtpNet;

namespace totp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MfaController : Controller
{

  private const string Rfc6238SecretSha1 = "12345678901234567890";
  private readonly byte[] secretKey = Encoding.UTF8.GetBytes(Rfc6238SecretSha1);
  private readonly int windowStep = 60;

  [HttpGet]
  [Route("generate")]
  [ProducesResponseType(typeof(string), 200)]
  public IActionResult Generate()
  {
    var totp = new Totp(secretKey, step: windowStep);
    return Ok(totp.ComputeTotp());
  }

  [HttpPost]
  [Route("verify")]
  public IActionResult Verify(string otp)
  {
    var totp = new Totp(secretKey, step: windowStep);
    if (totp.VerifyTotp(otp, out long matched, VerificationWindow.RfcSpecifiedNetworkDelay))
    {
      return Ok(totp.RemainingSeconds());
    }
    else 
    {
      return BadRequest(HttpStatusCode.BadRequest);
    }
  }

}