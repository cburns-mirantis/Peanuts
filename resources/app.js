$(document).foundation()
$("#r_1").change(function() {
    if(this.checked) {
      $("#customer_manager").prop("required",false)        
    }
});
$("#r_2").change(function() {
    if(this.checked) {
      $("#customer_manager").prop("required",false)
    }
});
$("#r_3").change(function() {
    if(this.checked) {
      $("#customer_manager").prop("required",true)
    }
});
