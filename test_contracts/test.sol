// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Enable optimizer with low runs for deployment size optimization
// solc --optimize --optimize-runs 1

import "./PropertyContract.sol";
import "./BuyContract.sol";
import "./TimestampFormatter.sol";

// Custom errors to reduce contract size
error OnlyAdmin();
error PropertyNotRentable();
error PropertyAlreadyRented();
error NotEnoughETH();
error RentalNotActive();
error NotTenant();
error InvalidRentalYears();
error InvalidPropertyId();
error NotEnoughShares();
error TransferFailed();
error InvalidAmount();
error PropertyNotFound();
error RentalNotFound();
error InvalidTenant();
error InvalidMonth();
error AlreadyPaid();
error NotOverdue();
error PaymentOverdue();
error InvalidOrderId();
error NotSeller();
error OrderNotActive();
error InvalidShareAmount();
error SellerCannotBuyOwn();
error IncorrectETH();
error InvalidValues();
error NotEnoughSharesToIncrease();
error NotEnoughSharesToTransfer();
error SharesMustBePositive();
error PriceMustBePositive();
error AdminNotAllowed();
error ReentrantCall();
error AdminPayoutFailed();
error ShareholderPayoutFailed();

contract RentalContract {
    using TimestampFormatter for uint256;

    PropertyContract public propertyContract;
    BuyContract public buyContract;

    uint256 public constant MONTH_DURATION = 60 seconds; // 1 month = 60 seconds (for testing)
    uint256 private nextTransactionId = 0;


    struct Rental {
        uint256 propertyId;
        address tenant;
        uint256 startDate;
        uint256 endDate;
        uint256 monthlyRent;
        uint256 deposit;
        uint256 paidMonths;
        uint256 rentalYears;
        bool active;
    }

    /// getAllActiveRentalFormatted
    struct RentalFormatted {
        uint256 propertyId;
        address tenant;
        address previousTenant;
        string propertyName;
        string propertyLocation;
        string startDate;
        string endDate;
        uint256 monthlyRent;
        uint256 deposit;
        uint256 paidMonths;
        uint256 rentalYears;
        bool active;
        string nextDueDate; 
    }


    // getAllRentalPaymentHistory
    struct PaymentRecord {
        uint256 timestamp;
        uint256 amount;
        uint8 paymentType; // 0=Rental, 1=Deposit
    }

    // getMyRental
    struct RentalWithProperty {
        // Rental details
        uint256 propertyId;
        string startDate;
        string endDate;
        uint256 rentalYears;
        uint256 paidMonths;
        uint256 monthlyRent;
        uint256 deposit;
        bool active;
        // Property details
        string name;
        string location;
        uint256 totalValue;
        uint256 remainingShares;
        string nextDueDate; 
    }

    struct PaymentDetail {
        uint256 propertyId;
        string propertyName;
        string propertyLocation;
        uint256 amount;
        string paidAt;
        address tenant;
        uint8 paymentType; // 0=Rental, 1=Deposit
    }


    struct ShareholderPayout {
        uint256 transactionId;   
        uint256 propertyId;
        string propertyName;
        string propertyLocation;
        uint256 amount;
        string receivedAt; 
        address tenant;
    }

    // Penalty record
    struct PenaltyRecord {
        uint256 propertyId;
        address tenant;
        uint256 amount;
        string reason;
        uint256 timestamp;
    }

    // Frontend data
    struct PenaltyRecordDetailed {
        uint256 propertyId;
        string propertyName;
        string propertyLocation;
        address tenant;
        uint256 amount;
        string reason;
        string timestamp; // formatted timestamp for better readability
    }

    // Group by property
    mapping(uint256 => PenaltyRecord[]) public penalties;

    // Also track penalties by tenant
    mapping(address => uint256[]) public tenantPenaltyProperties;
    mapping(address => mapping(uint256 => bool)) public tenantHasPenaltyProperty;


    // Event to emit when a penalty is applied
    event PenaltyApplied(
        uint256 indexed propertyId,
        address indexed tenant,
        uint256 amount,
        string reason,
        string timestamp
    );


    // Mapping: investor -> their payout history
    mapping(address => ShareholderPayout[]) private shareholderPayouts;

    mapping(uint256 => Rental) public activeRentals;
    mapping(uint256 => Rental[]) public rentalHistory;
    mapping(uint256 => address) public activeTenant;
    mapping(uint256 => PaymentRecord[]) public paymentHistory; // propertyId => payments

    // Track last tenant for each property
    mapping(uint256 => address) public previousTenant;



    event PropertyRented(
        uint256 indexed propertyId,
        address indexed tenant,
        uint256 deposit,
        uint256 monthlyRent,
        string startDate,
        string endDate
    );

    event MonthlyRentPaid(
        uint256 indexed propertyId,
        address indexed tenant,
        uint256 monthNumber,
        uint256 rentAmount,
        string paidAt 
    );

    event RentalEnded(
        uint256 indexed propertyId,
        address indexed tenant,
        uint256 depositRefunded
    );

    event RentDistributed(
        uint256 indexed propertyId,
        address indexed shareholder,
        uint256 amount,
        string receivedAt
    );

    constructor(address _propertyContract, BuyContract _buyContract) {
        propertyContract = PropertyContract(_propertyContract);
        buyContract = _buyContract;
    }

    // Get Shareholders' Payout
    function getMyPayouts(address investor)
        external
        view
        returns (ShareholderPayout[] memory)
    {
        return shareholderPayouts[investor];
    }

    // Get dividend history for a specific user (formatted for frontend)
    function getUserDividendHistory(address user) external view returns (
        uint256[] memory propertyIds,
        uint256[] memory amounts,
        string[] memory dates,
        address[] memory tenants
    ) {
        ShareholderPayout[] memory payouts = shareholderPayouts[user];
        uint256 length = payouts.length;
        
        propertyIds = new uint256[](length);
        amounts = new uint256[](length);
        dates = new string[](length);
        tenants = new address[](length);
        
        for (uint256 i = 0; i < length; i++) {
            propertyIds[i] = payouts[i].propertyId;
            amounts[i] = payouts[i].amount;
            dates[i] = payouts[i].receivedAt;
            tenants[i] = payouts[i].tenant;
        }
    }

    // Helper: record a single payout for one shareholder (split out to avoid "stack too deep")
    function _recordPayout(
        address shareholder,
        uint256 propertyId,
        uint256 amount,
        address tenantAddr
    ) internal {
        PropertyContract.Property memory p = propertyContract.getProperty(propertyId);

        shareholderPayouts[shareholder].push(
            ShareholderPayout({
                transactionId: nextTransactionId++,  
                propertyId: propertyId,
                propertyName: p.name,
                propertyLocation: p.location,
                amount: amount,
                receivedAt: block.timestamp.formatMalaysiaTimeWithSeconds(),
                tenant: tenantAddr
            })
        );

        emit RentDistributed(
            propertyId,
            shareholder,
            amount,
            block.timestamp.formatMalaysiaTimeWithSeconds()
        );

        nextTransactionId++; 
    }


    // --- Rent = 0.01% of property value monthly (cheap for testing) ---
    function getMonthlyRent(uint256 _propertyId) public view returns (uint256) {
        PropertyContract.Property memory prop = propertyContract.getProperty(
            _propertyId
        );
        uint256 monthlyRentInETH = (prop.totalValue * 1) / 10000; // fix: 0.01%
        return monthlyRentInETH * 1 ether;
    }

    // at least 1% shares bought then can be rented
    function isRentable(uint256 _propertyId) public view returns (bool) {
        if (_propertyId >= propertyContract.getPropertyCount()) revert InvalidPropertyId();

        // Check if property has at least 1% shares bought
        PropertyContract.Property memory prop = propertyContract.getProperty(
            _propertyId
        );
        uint256 totalShares = propertyContract.TOTAL_SHARES(); // should be 10000 fixed
        uint256 minSharesRequired = totalShares / 100; // 1% = 100

        // Calculate shares already bought
        uint256 boughtShares = totalShares - prop.shares;
        bool enoughBought = boughtShares >= minSharesRequired;

        // Check rental status
        Rental storage r = activeRentals[_propertyId];
        if (r.active && block.timestamp <= r.endDate) {
            return false; // already rented
        }

        return enoughBought;
    }

    // Start rental
    function startRental(uint256 _propertyId, uint256 _rentalYears)
        external
        payable
    {
        if (_rentalYears < 1) revert InvalidRentalYears();
        if (!isRentable(_propertyId)) revert PropertyNotRentable();
        if (msg.sender == propertyContract.admin()) revert AdminNotAllowed();

        uint256 monthlyRent = getMonthlyRent(_propertyId);
        uint256 deposit = monthlyRent * 2;
        uint256 upfront = deposit + monthlyRent;

        if (msg.value < upfront) revert NotEnoughETH();

        uint256 startEpoch = block.timestamp;
        uint256 endEpoch = startEpoch + (_rentalYears * 12 * MONTH_DURATION);

        activeRentals[_propertyId] = Rental({
            propertyId: _propertyId,
            tenant: msg.sender,
            startDate: startEpoch, // keep epoch for math
            endDate: endEpoch, // keep epoch for math
            monthlyRent: monthlyRent,
            deposit: deposit,
            paidMonths: 1,
            rentalYears: _rentalYears,
            active: true
        });

        activeTenant[_propertyId] = msg.sender;

        // Save payment history (first month)
        paymentHistory[_propertyId].push(
            PaymentRecord({
                timestamp: block.timestamp,
                amount: monthlyRent,
                paymentType: 0 // 0 = rental payment
            })
        );


        // Pay out the first month
        _distributeRent(_propertyId, monthlyRent);

        // Refund excess ETH if tenant overpaid
        if (msg.value > upfront) {
            (bool refundOk, ) = payable(msg.sender).call{
                value: msg.value - upfront
            }("");
            if (!refundOk) revert TransferFailed();
        }

        // Save rental history
        rentalHistory[_propertyId].push(activeRentals[_propertyId]);

        // Only format for events
        emit PropertyRented(
            _propertyId,
            msg.sender,
            deposit,
            monthlyRent,
            startEpoch.formatMalaysiaTimeWithSeconds(),
            endEpoch.formatMalaysiaTimeWithSeconds()
        );
    }

    // Pay monthly rent
    function payMonthlyRent(uint256 _propertyId) external payable {
        Rental storage r = activeRentals[_propertyId];
        if (!r.active) revert RentalNotActive();
        if (msg.sender != r.tenant) revert NotTenant();
        if (r.paidMonths >= r.rentalYears * 12) revert AlreadyPaid();

        // Calculate due date for the NEXT payment
        uint256 dueDate = r.startDate + (r.paidMonths * MONTH_DURATION);

        // Block payment if already overdue
        if (block.timestamp > dueDate) revert PaymentOverdue();

        if (msg.value < r.monthlyRent) revert NotEnoughETH();

        r.paidMonths += 1;

        // Save payment history
        paymentHistory[_propertyId].push(
            PaymentRecord({
                timestamp: block.timestamp,
                amount: r.monthlyRent,
                paymentType: 0 // 0 = rental payment
            })
        );

        _distributeRent(_propertyId, r.monthlyRent);

        // Refund excess ETH
        if (msg.value > r.monthlyRent) {
            (bool refundOk, ) = payable(msg.sender).call{
                value: msg.value - r.monthlyRent
            }("");
            if (!refundOk) revert TransferFailed();
        }

        emit MonthlyRentPaid(
            _propertyId,
            msg.sender,
            r.paidMonths,
            r.monthlyRent,
            block.timestamp.formatMalaysiaTimeWithSeconds()
        );
    }

    // End rental
    function endRental(uint256 _propertyId) external {
        Rental storage r = activeRentals[_propertyId];
        if (!r.active) revert RentalNotActive();
        if (msg.sender != r.tenant) revert NotTenant();

        // Ensure rental is actually finished
        if (block.timestamp < r.endDate && r.paidMonths < r.rentalYears * 12) revert RentalNotActive();

        r.active = false;

        // Save tenant as previous tenant
        previousTenant[_propertyId] = r.tenant;
        activeTenant[_propertyId] = address(0);

        // Refund deposit
        uint256 depositAmount = r.deposit;
        r.deposit = 0;

        (bool refundOk, ) = payable(msg.sender).call{value: depositAmount}("");
        if (!refundOk) revert TransferFailed();

        // Record deposit refund in payment history
        paymentHistory[_propertyId].push(
            PaymentRecord({
                timestamp: block.timestamp,
                amount: depositAmount,
                paymentType: 1 // Deposit Refund
            })
        );

        emit RentalEnded(_propertyId, msg.sender, depositAmount);
    }




    // Enforce penalty
    function enforcePenalty(uint256 _propertyId) external {
        Rental storage r = activeRentals[_propertyId];
        if (!r.active) revert RentalNotActive();
        if (msg.sender != propertyContract.admin()) revert OnlyAdmin();

        uint256 dueDate = r.startDate + (r.paidMonths * MONTH_DURATION);
        if (block.timestamp <= dueDate) revert NotOverdue();

        // Step 1: forfeit deposit if overdue
        if (r.deposit > 0) {
            uint256 forfeited = r.deposit;
            r.deposit = 0;

            // Record penalty for deposit forfeiture
            penalties[_propertyId].push(PenaltyRecord({
                propertyId: _propertyId,
                tenant: r.tenant,
                amount: forfeited,
                reason: "Late",
                timestamp: block.timestamp
            }));

            // Update tenant penalty tracking
            if (!tenantHasPenaltyProperty[r.tenant][_propertyId]) {
                tenantPenaltyProperties[r.tenant].push(_propertyId);
                tenantHasPenaltyProperty[r.tenant][_propertyId] = true;
            }

            (bool sent, ) = payable(propertyContract.admin()).call{value: forfeited}("");
            require(sent, "Deposit transfer failed");

            r.active = false;
            activeTenant[_propertyId] = address(0);

            emit RentalEnded(_propertyId, r.tenant, 0); // deposit already gone
        }
    }

    // --- Return all overdue rentals ---
    function getOverdueRentals()
        external
        view
        returns (
            uint256[] memory,
            address[] memory,
            uint256[] memory
        )
    {
        uint256 total = propertyContract.getPropertyCount();

        // First count overdue rentals
        uint256 overdueCount = 0;
        for (uint256 i = 0; i < total; i++) {
            Rental memory r = activeRentals[i];
            if (r.active) {
                uint256 dueDate = r.startDate + (r.paidMonths * MONTH_DURATION);
                if (
                    block.timestamp > dueDate &&
                    r.paidMonths < r.rentalYears * 12
                ) {
                    overdueCount++;
                }
            }
        }

        // Build arrays
        uint256[] memory propertyIds = new uint256[](overdueCount);
        address[] memory tenants = new address[](overdueCount);
        uint256[] memory overdueMonths = new uint256[](overdueCount);

        uint256 j = 0;
        for (uint256 i = 0; i < total; i++) {
            Rental memory r = activeRentals[i];
            if (r.active) {
                uint256 dueDate = r.startDate + (r.paidMonths * MONTH_DURATION);
                if (
                    block.timestamp > dueDate &&
                    r.paidMonths < r.rentalYears * 12
                ) {
                    propertyIds[j] = i;
                    tenants[j] = r.tenant;
                    overdueMonths[j] = r.paidMonths + 1; // the month they should have paid
                    j++;
                }
            }
        }

        return (propertyIds, tenants, overdueMonths);
    }

    ///////////////////////////////// Rental Distribution (dividend part) - Updated Logic
    function _distributeRent(uint256 _propertyId, uint256 rentAmount) private {
        uint256 commission = (rentAmount * 10) / 100;
        uint256 distributable = rentAmount - commission;
        
        _distributeAdminPayout(_propertyId, commission, distributable);
        _distributeShareholderPayouts(_propertyId, distributable);
    }
    
    function _distributeAdminPayout(uint256 _propertyId, uint256 commission, uint256 distributable) private {
        PropertyContract.Property memory property = propertyContract.getProperty(_propertyId);
        address adminAddr = propertyContract.admin();
        
        if (adminAddr != address(0)) { // Check for valid admin address
            uint256 adminSharePayout = (distributable * property.shares) / 10000;
            uint256 totalAdminPayout = commission + adminSharePayout;
            
            if (totalAdminPayout > 0) {
                (bool sentAdmin, ) = payable(adminAddr).call{value: totalAdminPayout}("");
                if (!sentAdmin) revert AdminPayoutFailed();
                _recordPayout(adminAddr, _propertyId, totalAdminPayout, activeTenant[_propertyId]);
            }
        }
    }
    
    function _distributeShareholderPayouts(uint256 _propertyId, uint256 distributable) private {
        address[] memory shareholders = buyContract.getPropertyShareholders(_propertyId);
        address tenantAddr = activeTenant[_propertyId];
        
        for (uint256 i = 0; i < shareholders.length; i++) {
            if (shareholders[i] != address(0)) { // Check for valid address
                uint256 holderShares = buyContract.getUserShares(_propertyId, shareholders[i]);
                if (holderShares > 0) { // Only process if user has shares
                    uint256 payout = (distributable * holderShares) / 10000;
                    
                    if (payout > 0) {
                        (bool ok, ) = payable(shareholders[i]).call{value: payout}("");
                        if (!ok) revert ShareholderPayoutFailed();
                        _recordPayout(shareholders[i], _propertyId, payout, tenantAddr);
                    }
                }
            }
        }
    }

    // --- View payment history ---
    function getPaymentHistory(uint256 _propertyId)
        external
        view
        returns (string[] memory, uint256[] memory)
    {
        PaymentRecord[] memory records = paymentHistory[_propertyId];
        string[] memory dates = new string[](records.length);
        uint256[] memory amounts = new uint256[](records.length);

        for (uint256 i = 0; i < records.length; i++) {
            dates[i] = records[i].timestamp.formatMalaysiaTimeWithSeconds();
            amounts[i] = records[i].amount;
        }

        return (dates, amounts);
    }

    // --- Check next due date ---
    function getNextDueDate(uint256 _propertyId)
        external
        view
        returns (string memory, uint256)
    {
        Rental memory r = activeRentals[_propertyId];
        if (!r.active) revert RentalNotActive();

        uint256 nextDue = r.startDate + (r.paidMonths * MONTH_DURATION);
        string memory formatted = nextDue.formatMalaysiaTimeWithSeconds();

        uint256 remainingMonths = (r.endDate - nextDue) / MONTH_DURATION;

        return (formatted, remainingMonths);
    }

    // Return all properties that are currently rentable
    function getAllRentableProperties()
        external
        view
        returns (PropertyContract.Property[] memory)
    {
        uint256 total = propertyContract.getPropertyCount();
        uint256 rentableCount = 0;

        // First loop  count rentable properties
        for (uint256 i = 0; i < total; i++) {
            if (isRentable(i)) {
                rentableCount++;
            }
        }

        // Second loop  collect rentable properties
        PropertyContract.Property[]
            memory rentableProps = new PropertyContract.Property[](
                rentableCount
            );
        uint256 j = 0;
        for (uint256 i = 0; i < total; i++) {
            if (isRentable(i)) {
                rentableProps[j] = propertyContract.getProperty(i);
                j++;
            }
        }

        return rentableProps;
    }

    function getMyRentals(address tenant) external view returns (RentalWithProperty[] memory) {
        uint256 total = propertyContract.getPropertyCount();
        uint256 count = 0;
        for (uint256 i = 0; i < total; i++) {
            if (activeRentals[i].tenant == tenant && activeRentals[i].active) count++;
        }
        RentalWithProperty[] memory results = new RentalWithProperty[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < total; i++) {
            Rental memory r = activeRentals[i];
            if (r.tenant == tenant && r.active) {
                PropertyContract.Property memory p = propertyContract.getProperty(i);
                results[j].propertyId = i;
                results[j].startDate = r.startDate.formatMalaysiaTimeWithSeconds();
                results[j].endDate = r.endDate.formatMalaysiaTimeWithSeconds();
                results[j].rentalYears = r.rentalYears;
                results[j].paidMonths = r.paidMonths;
                results[j].monthlyRent = r.monthlyRent;
                results[j].deposit = r.deposit;
                results[j].active = r.active;
                results[j].name = p.name;
                results[j].location = p.location;
                results[j].totalValue = p.totalValue;
                results[j].remainingShares = p.shares;
                uint256 nextDue = r.startDate + (r.paidMonths * MONTH_DURATION);
                results[j].nextDueDate = nextDue.formatMalaysiaTimeWithSeconds();
                j++;
            }
        }
        return results;
    }

    function getMyRentalPaymentHistory(address tenant) external view returns (PaymentDetail[] memory) {
        uint256 total = propertyContract.getPropertyCount();
        uint256 totalRecords = 0;
        for (uint256 i = 0; i < total; i++) {
            if (activeRentals[i].tenant == tenant) {
                totalRecords += paymentHistory[i].length;
            }
        }
        PaymentDetail[] memory records = new PaymentDetail[](totalRecords);
        uint256 idx = 0;
        for (uint256 i = 0; i < total; i++) {
            if (activeRentals[i].tenant == tenant) {
                PropertyContract.Property memory p = propertyContract.getProperty(i);
                for (uint256 j = 0; j < paymentHistory[i].length; j++) {
                    PaymentRecord memory rec = paymentHistory[i][j];
                    records[idx] = PaymentDetail({
                        propertyId: i,
                        propertyName: p.name,
                        propertyLocation: p.location,
                        amount: rec.amount,
                        paidAt: rec.timestamp.formatMalaysiaTimeWithSeconds(),
                        tenant: tenant,
                        paymentType: rec.paymentType
                    });
                    idx++;
                }
            }
        }
        return records;
    }



    function getAllRentalPaymentHistory() external view returns (PaymentDetail[] memory) {
        uint256 totalProps = propertyContract.getPropertyCount();
        uint256 totalRecords = 0;
        for (uint256 i = 0; i < totalProps; i++) {
            totalRecords += paymentHistory[i].length;
        }
        PaymentDetail[] memory records = new PaymentDetail[](totalRecords);
        uint256 idx = 0;
        for (uint256 i = 0; i < totalProps; i++) {
            PropertyContract.Property memory p = propertyContract.getProperty(i);
            for (uint256 j = 0; j < paymentHistory[i].length; j++) {
                PaymentRecord memory rec = paymentHistory[i][j];
                address tenantAddr = address(0);
                Rental memory ar = activeRentals[i];
                if (ar.active && rec.timestamp >= ar.startDate && rec.timestamp <= ar.endDate) {
                    tenantAddr = ar.tenant;
                }
                if (tenantAddr == address(0)) {
                    for (uint256 k = 0; k < rentalHistory[i].length; k++) {
                        Rental memory hist = rentalHistory[i][k];
                        if (rec.timestamp >= hist.startDate && rec.timestamp <= hist.endDate) {
                            tenantAddr = hist.tenant;
                            break;
                        }
                    }
                }
                records[idx] = PaymentDetail({
                    propertyId: i,
                    propertyName: p.name,
                    propertyLocation: p.location,
                    amount: rec.amount,
                    paidAt: rec.timestamp.formatMalaysiaTimeWithSeconds(),
                    tenant: tenantAddr,
                    paymentType: rec.paymentType
                });
                idx++;
            }
        }
        return records;
    }


    // Get active rental formatted
    function getActiveRentalFormatted(uint256 _propertyId)
        external
        view
        returns (
            uint256 propertyId,
            address tenant,
            address previousTenantAddr,
            string memory startDate,
            string memory endDate,
            uint256 monthlyRent,
            uint256 deposit,
            uint256 paidMonths,
            uint256 rentalYears,
            bool active
        )
    {
        Rental memory r = activeRentals[_propertyId];

        if (!r.active) {
            return (
                _propertyId,
                address(0),
                previousTenant[_propertyId],
                "",
                "",
                0,
                0,
                0,
                0,
                false
            );
        }

        return (
            r.propertyId,
            r.tenant,
            previousTenant[_propertyId], //  return last known tenant
            r.startDate.formatMalaysiaTimeWithSeconds(),
            r.endDate.formatMalaysiaTimeWithSeconds(),
            r.monthlyRent,
            r.deposit,
            r.paidMonths,
            r.rentalYears,
            r.active
        );
    }


    function getAllActiveRentalFormatted() external view returns (RentalFormatted[] memory) {
        uint256 total = propertyContract.getPropertyCount();
        uint256 count = 0;
        for (uint256 i = 0; i < total; i++) {
            if (activeRentals[i].active) count++;
        }
        RentalFormatted[] memory records = new RentalFormatted[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < total; i++) {
            Rental memory r = activeRentals[i];
            if (r.active) {
                PropertyContract.Property memory p = propertyContract.getProperty(i);
                uint256 nextDueEpoch = r.startDate + (r.paidMonths * MONTH_DURATION);
                records[idx] = RentalFormatted({
                    propertyId: r.propertyId,
                    tenant: r.tenant,
                    previousTenant: previousTenant[i],
                    propertyName: p.name,
                    propertyLocation: p.location,
                    startDate: r.startDate.formatMalaysiaTimeWithSeconds(),
                    endDate: r.endDate.formatMalaysiaTimeWithSeconds(),
                    monthlyRent: r.monthlyRent,
                    deposit: r.deposit,
                    paidMonths: r.paidMonths,
                    rentalYears: r.rentalYears,
                    active: r.active,
                    nextDueDate: nextDueEpoch.formatMalaysiaTimeWithSeconds()
                });
                idx++;
            }
        }
        return records;
    }



    // Rental history
    function getRentalHistory(uint256 _propertyId)
        external
        view
        returns (Rental[] memory)
    {
        return rentalHistory[_propertyId];
    }

    // Get all penalty records for a tenant
    function getPenaltyRecords(address _tenant)
        external
        view
        returns (PenaltyRecordDetailed[] memory)
    {
        uint256 totalProps = tenantPenaltyProperties[_tenant].length;

        // First, count total records for this tenant
        uint256 totalRecords = 0;
        for (uint256 i = 0; i < totalProps; i++) {
            uint256 propId = tenantPenaltyProperties[_tenant][i];

            for (uint256 j = 0; j < penalties[propId].length; j++) {
                if (penalties[propId][j].tenant == _tenant) {
                    totalRecords++;
                }
            }
        }

        // Build result array
        PenaltyRecordDetailed[] memory results = new PenaltyRecordDetailed[](totalRecords);
        uint256 idx = 0;

        for (uint256 i = 0; i < totalProps; i++) {
            uint256 propId = tenantPenaltyProperties[_tenant][i];
            PropertyContract.Property memory prop = propertyContract.getProperty(propId);

            for (uint256 j = 0; j < penalties[propId].length; j++) {
                PenaltyRecord memory p = penalties[propId][j];

                if (p.tenant == _tenant) {
                    results[idx] = PenaltyRecordDetailed({
                        propertyId: propId,
                        propertyName: prop.name,
                        propertyLocation: prop.location,
                        tenant: p.tenant,
                        amount: p.amount,
                        reason: p.reason,
                        timestamp: p.timestamp.formatMalaysiaTimeWithSeconds()
                    });
                    idx++;
                }
            }
        }

        return results;
    }


    function getAllPenaltyRecords()
        external
        view
        returns (PenaltyRecordDetailed[] memory)
    {
        uint256 totalProps = propertyContract.getPropertyCount();

        // Count all penalty records
        uint256 totalRecords = 0;
        for (uint256 i = 0; i < totalProps; i++) {
            totalRecords += penalties[i].length;
        }

        PenaltyRecordDetailed[] memory results = new PenaltyRecordDetailed[](totalRecords);
        uint256 idx = 0;

        for (uint256 i = 0; i < totalProps; i++) {
            PropertyContract.Property memory prop = propertyContract.getProperty(i);

            for (uint256 j = 0; j < penalties[i].length; j++) {
                PenaltyRecord memory p = penalties[i][j];

                results[idx] = PenaltyRecordDetailed({
                    propertyId: i,
                    propertyName: prop.name,
                    propertyLocation: prop.location,
                    tenant: p.tenant,
                    amount: p.amount,
                    reason: p.reason,
                    timestamp: p.timestamp.formatMalaysiaTimeWithSeconds()
                });
                idx++;
            }
        }

        return results;
    }

// ONLY FOR TESTING – REMOVE IN PRODUCTION
    function debugAdvanceTime(uint256 secondsToAdvance) external {
        // Add safety: only admin can call
        require(msg.sender == propertyContract.admin(), "Only admin");

        // Trick: pretend startDate shifted backwards in time
        for (uint256 i = 0; i < propertyContract.getPropertyCount(); i++) {
            if (activeRentals[i].active) {
                activeRentals[i].startDate -= secondsToAdvance;
            }
        }
    }
    receive() external payable {}

    fallback() external payable {}
}


