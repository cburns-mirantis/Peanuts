$(document).foundation()
$("#r_1").change(function() {
    if(this.checked) {
      $("#customer_manager").prop("required",false)
      $("#customer_manager").removeClass('is-invalid-input')
      $("#cs_label").removeClass('is-invalid-label')
    }
});
$("#r_2").change(function() {
    if(this.checked) {
      $("#customer_manager").prop("required",false)
      $("#customer_manager").removeClass('is-invalid-input')
      $("#cs_label").removeClass('is-invalid-label')
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
  .on("submit", function(ev) {
    ev.preventDefault();
    var loading_modal = new Foundation.Reveal($('#loading_modal'));
    var complete_modal = new Foundation.Reveal($('#complete_modal'));
    var error_modal = new Foundation.Reveal($('#error_modal'));
    loading_modal.open();
    $.post("cgi/report.py", $("#form").serialize(), function(data) {
      $("#complete_modal_content").replaceWith(data);
      loading_modal.close();
      complete_modal.open();
    }).fail(function(response){
      $("#error_modal_content").replaceWith(response.responseText);
      loading_modal.close();
      error_modal.open()
    });
  });
