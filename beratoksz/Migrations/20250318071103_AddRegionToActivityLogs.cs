using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace beratoksz.Migrations
{
    /// <inheritdoc />
    public partial class AddRegionToActivityLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Region",
                table: "ActivityLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Region",
                table: "ActivityLogs");
        }
    }
}
