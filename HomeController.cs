using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LogReg.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace LogReg.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

      private MyContext _context;

    public HomeController(ILogger<HomeController> logger,  MyContext context)
    {
        _logger = logger;
         _context = context;


    }

    public IActionResult Index()
    {
        return View("Index");
    }




    [HttpPost("register")]
    public IActionResult Register(User newUser)
    {
        if(!ModelState.IsValid)
        {
            return Index();
        }
        PasswordHasher<User> hashBrowns = new PasswordHasher<User>();
        newUser.Password = hashBrowns.HashPassword(newUser, newUser.Password);
        _context.Users.Add(newUser);
        _context.SaveChanges();

        HttpContext.Session.SetInt32("UUID", newUser.UserId);
        return RedirectToAction("Success");

    }


    [HttpGet("success")]
    public IActionResult Success()
    {
        return View("Success");
    }


    [HttpPost("login")]
    public IActionResult Login(LoginUser loginUser)
    {
        if(!ModelState.IsValid)
        {
            return Index();
        }
        User? dbUser = _context.Users.FirstOrDefault(user => user.Email == loginUser.LoginEmail);
        if(dbUser == null)
        {
            ModelState.AddModelError("Email", "not found");
            return Index();
        }
        PasswordHasher<LoginUser> hashBrowns = new PasswordHasher<LoginUser>();
        PasswordVerificationResult pwCompareResult = hashBrowns.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);

        if(pwCompareResult == 0)
        {
            ModelState.AddModelError("LoginPassword", "invalid password");
        }
        HttpContext.Session.SetInt32("UUID", dbUser.UserId);
        return RedirectToAction("Success");
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
