using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CentralizedOAuthClient.Extemtion;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace CentralizedOAuthClient
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string wrongPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06pYm1ahzazvS17zSZtQnqeE/fjJBcDNqVeD/kMqctBExND22PMoU9v1kmEvunhShIHPA3blgpLoOaQQD2+BiCwMZjCbAMEIwEl//sYvnICDUv4+UCMn6obwyhGEAldOwMxeVdocDdnAsvIaYflmSaec/ZP11EjZ+zujgimoO+7DxjZ652hTCPd9Mc7Z0i+lCM5MLK1PpNfYmUcwgI9yrOMQapCKKrURM/6XwEMP5gtLN7IXRUkZvI3zrCpD95Dr//x7s/jinylEWLoo7WKk6/eq9eXQOnCS47OMt/Mey4x3nSbZsCTvL2q3/xyselFZyRlfoc8eIqdd6cv6cQe0aQIDAQAB-----END PUBLIC KEY-----";
            string publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoT2r2y1s/BmiOSzW4mhax90NrPZY16D83ax74BxQS1r37Lw20ozK3ZoCWSnJ1vT0Fwd1wFRJ05xZku+dRPkYkWh9Kx+5+QAh7XCZM8e+8DXtxOomx7DZsBPrjw+MU0FpQltkz9Z/2YA3CDR3HQmc0F1YmTs7CQSNxD5vW1gyGgc4y306XKiWKT0B2rCxCNoZmNH2H/Y+5XlHTRVdn3yKTfJM2ga5fCQRbMxb+gP+aANF8S6SyDN1S3gW1ZtY9rXNkXmBZqWHFPJ2LmVQk+S74w+xUjpvAkPgx1o7hkQkf06wLlQRISZ1gbxcsfxYZyKTVVSHn6pPObT25aytqVLmpQIDAQAB-----END PUBLIC KEY-----";
            string validIssuer = "https://www.testing.com";

            var authPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .Build();

            services.AddControllers();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddJwtBearer(options =>
               {
                   //options.Authority = "https://localhost:44391/validate";
                   options.TokenValidationParameters = new TokenValidationParameters
                   {
                       IssuerSigningKey = RSASecurityKey(publicKey),
                       RequireExpirationTime = true,
                       ValidateAudience = false,
                       ValidateIssuer = true,
                       ValidateIssuerSigningKey = true,
                       ValidateLifetime = true,
                       ValidIssuer = validIssuer,
                       ClockSkew = TimeSpan.Zero
                   };
               });

            services.AddMvc(options =>
            {
                options.Filters.Add(new AuthorizeFilter(authPolicy));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private RsaSecurityKey RSASecurityKey(string publicKey)
        {
            var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
            rsa.LoadPublicKeyPEM(publicKey);
            return new RsaSecurityKey(rsa);
        }
    }
}
