using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


[NotMapped]
public class LoginUser
{

    [Required(ErrorMessage = "is required")]
    [EmailAddress]
    public string LoginEmail {get;set;}

    [Required(ErrorMessage = "is required")]
    [MinLength(8, ErrorMessage = "must be atleast 8 characters.")]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string LoginPassword {get; set;}
}