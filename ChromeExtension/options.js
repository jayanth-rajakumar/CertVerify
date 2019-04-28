function save_options() {
    var method = document.getElementById('method').value;
    var block = document.getElementById('block').checked;
    var ocsphardfail = document.getElementById('ocsphardfail').checked;
    chrome.storage.sync.set({
      chosenmethod: method,
      chosenblock: block,
      chosenocsphardfail: ocsphardfail
    }, function() {
      // Update status to let user know options were saved.
      var status = document.getElementById('status');
      status.textContent = 'Options saved.';
      setTimeout(function() {
        status.textContent = '';
      }, 750);
    });
  }
  
  // Restores select box and checkbox state using the preferences
  // stored in chrome.storage.
  function restore_options() {
    
    chrome.storage.sync.get({
      chosenmethod: 'crl',
      chosenblock: false,
      chosenocsphardfail: false
    }, function(items) {
      document.getElementById('method').value = items.chosenmethod;
      document.getElementById('block').checked = items.chosenblock;
      document.getElementById('ocsphardfail').checked = items.chosenocsphardfail;
    });
  }
  document.addEventListener('DOMContentLoaded', restore_options);
  document.getElementById('save').addEventListener('click',
      save_options);