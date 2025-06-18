const LEGAL_AGE = 18;

const dateHelper = {
  formatDateForMysql(dateString = null) {
    const date = dateString ? new Date(dateString) : new Date();
    console.log('formatDateForMysql', date);
    return date.toISOString().slice(0, 19).replace('T', ' ');
  },
  getAge(dateString) {
    var today = new Date();
    var birthDate = new Date(dateString);
    var age = today.getFullYear() - birthDate.getFullYear();
    var m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    return age;
  },
  isLegalAge(dateUser) {
    const age = this.getAge(dateUser);
    return age >= LEGAL_AGE;
  },
  getBirthDateOfDateAge(ageNumber) {
    const date = new Date();
    date.setFullYear( date.getFullYear() - ageNumber );
    console.log('getBirthDateOfDateAge date', date);
    console.log('getBirthDateOfDateAge getAge', this.getAge(date));
    return this.formatDateForMysql(date);
  },
  getDateMinusXHours(hours) {
    const date = new Date();
    date.setHours(date.getHours() - hours);
    return this.formatDateForMysql(date);
  },
  getDateMinusXMinutes(dateGtmString, minutes) {
    console.log('dateGtmString', dateGtmString);
    console.log('minutes', minutes);

    const d = new Date(dateGtmString);
    console.log('d', d);

    d.setMinutes(d.getMinutes() - minutes);
    console.log('d', d);

    return this.formatDateForMysql(d);
  },
  getUserDateFromOffset(date, offset) {
    return this.formatDateForMysql(date.setMinutes(date.getMinutes() + offset));
  },
}

module.exports = dateHelper;
