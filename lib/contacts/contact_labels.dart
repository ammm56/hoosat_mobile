import 'contact.dart';

const kKaspaDevFundAddress =
    'hoosat:qq5gtjz7xhghcyauyhwmy9a696ym7nhaj857t32l25qqysyzz27lzy9esv046';

const kCommunityMarketingFundAddress =
    'hoosat:qry9xevl44e8pyvkkkp5wnvavyg59rge6j0yhgg70wzqepuw6t28jqg34hgh5';

const kDonationAddresses = const [
  Contact(
    name: 'Hoosat Dev Fund',
    address: kKaspaDevFundAddress,
  ),
  Contact(
    name: 'Community Marketing Fund',
    address: kCommunityMarketingFundAddress,
  )
];

final labeledAddresses = Map.fromEntries(
  kDonationAddresses.map((e) => MapEntry(e.address, e)),
);
