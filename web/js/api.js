var dcrAmount = 0;
var priceApi = 0;
var currencyApi = "usd";

$('document').ready(function() {
    var getBalance = $('#btn-balance');
    getBalance.click(function() {
        callAPI('/api/balance', callbackBalance);
    });
    var getTickets = $('#btn-tickets');
    getTickets.click(function() {
        callAPI('/api/tickets', callbackTickets);
    });
    callPriceUpdate("decred", currencyApi)
});

function callbackBalance(result) {
    dcrAmount = result.amount;
    $('#balance-view h2').text("Balance: " + currencyApi.toUpperCase() + " " + (dcrAmount * priceApi).toFixed(2));
    $('#balance-view h2').append(" (DCR " + dcrAmount + ")")
}

function callbackTickets(result) {
    ownMempool = result.ownMempool;
    immature = result.immature;
    live = result.live;
    totalSubsidy = result.totalSubsidy;
    selectedCurrency = currencyApi.toUpperCase();
    $('#tickets-view h2').text("");
    $('#tickets-view h2').append("OwnMempool: " + selectedCurrency + " " + (ownMempool * priceApi).toFixed(2));
    $('#tickets-view h2').append(" | ");
    $('#tickets-view h2').append("Immature: " + selectedCurrency + " " + (immature * priceApi).toFixed(2));
    $('#tickets-view h2').append(" | ");
    $('#tickets-view h2').append("Live: " + selectedCurrency + " " + (live * priceApi).toFixed(2));
    $('#tickets-view h2').append(" | ");
    $('#tickets-view h2').append("Total Subsidy: " + selectedCurrency + " " + (totalSubsidy * priceApi).toFixed(2));
}

function callbackPriceUpdate(price) {
    priceApi = price;
}

function callAPI(endpoint, callbackFunction) {
    var accessToken = localStorage.getItem('access_token');
  
    var headers;
    if (accessToken) {
      headers = { Authorization: 'Bearer ' + accessToken };
    }
  
    $.ajax({
      url: endpoint,
      headers: headers
    })
      .done(function(result) {
        callbackFunction(result);
      })
      .fail(function(err) {
        $('#call-message h2').text('Request failed: ' + err.statusText);
      });
}

function callPriceUpdate(tickerId, currency) {
    var endpoint = "https://api.coinmarketcap.com/v1/ticker/" + tickerId + "/?convert=" + currency;
    $.ajax({
        url: endpoint
      })
        .done(function(result) {
          callbackPriceUpdate(result[0]["price_"+currency]);
        })
        .fail(function(err) {
          $('#balance-view h2').text('CoinMarketCap API Request failed: ' + err.statusText);
        });
}