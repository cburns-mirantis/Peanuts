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
      $("#customer_manager").addClass('is-invalid-input')
      $("#cs_label").addClass('is-invalid-label')
    }
});
$(document)
  // form validation passed, form will submit if submit event not returned false
  // .on("formvalid.zf.abide", function(ev,frm) {
  //   console.log("Form id "+frm.attr('id')+" is valid");
  //   // ajax post form
  // })
  .on("submit", function(ev) {
    ev.preventDefault();
    $.post("cgi/report.py", $("#form").serialize(), function(data) {
        console.log(data);
    });
    var popup = new Foundation.Reveal($('#modal'));
    popup.open();
  });
