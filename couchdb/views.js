// Author: Goran Cetusic
// Email: goran.cetusic@gmail.com, goran.cetusic@cern.ch
// Description: These are the CouchDB views for CERN lxbatch process accounting.

// Active users per machine (records)
function(doc) {
  var user;
  if (doc.ProbeName && doc.UserID) {
    for (user in doc.UserID) {
      emit(doc.ProbeName, doc.UserID[user]);
    }
  }
}

function(keys, values) {
  var uniUsers=new Array();
  values.sort();
  for(var i=0; i<values.length; i++) {
    if(values[i]==values[i+1]) {continue}
    uniUsers[uniUsers.length]=values[i];
  }
  return uniUsers;
}

// Machines where users were active (records)
function(doc) {
  var user;
  if (doc.ProbeName && doc.UserID) {
    for (user in doc.UserID) {
      emit(doc.UserID[user], doc.ProbeName);
    }
  }
}

function(keys, values) {
  var uniUsers=new Array();
  values.sort();
  for(var i=0; i<values.length; i++) {
    if(values[i]==values[i+1]) {continue}
    uniUsers[uniUsers.length]=values[i];
  }
  return uniUsers;
}
