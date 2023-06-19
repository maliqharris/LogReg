
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LogReg.Models
{
    public class User
    {
        [Key]
        public int UserId {get;set;}
        [Required]
        [MinLength(2, ErrorMessage = "must be atleast 2 characters.")]
        public string FirstName {get;set;}
        [Required]
        [MinLength(2, ErrorMessage = "must be atleast 2 characters.")]
        public string LastName {get;set;}
        [Required]
        [EmailAddress]
        [UniqueEmail]
        [MinLength(2, ErrorMessage = "must be atleast 2 characters.")]
        public string Email {get;set;}
        [Required]
        [MinLength(8, ErrorMessage = "must be atleast 8 characters.")]
        [DataType(DataType.Password)]
        public string Password {get;set;}



        [NotMapped]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Must match password")]
        public string PasswordConfirm {get;set;}
            
        public DateTime CreatedAt {get;set;} = DateTime.Now;
        public DateTime UpdatedAt {get;set;} = DateTime.Now;

    }
    public class UniqueEmailAttribute : ValidationAttribute
    {
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
    	// Though we have Required as a validation, sometimes we make it here anyways
    	// In which case we must first verify the value is not null before we proceed
            if(value == null)
            {
                // If it was, return the required error
                return new ValidationResult("Email is required!");
            }
        
            // This will connect us to our database since we are not in our Controller
            MyContext _context = (MyContext)validationContext.GetService(typeof(MyContext));
            // Check to see if there are any records of this email in our database
            if(_context.Users.Any(e => e.Email == value.ToString()))
            {
                // If yes, throw an error
                return new ValidationResult("Email must be unique!");
            } else {
                // If no, proceed
                return ValidationResult.Success;
            }
        }
    }


}